; ===========================================================================
; Triage mode (--triage / -t)
;
; A single pass that flags the anomalies a reverse-engineer or secops reviewer
; cares about, ranked by severity (HIGH / MED / LOW / INFO), ending with a
; one-line summary.  It reuses the facts already gathered by validate_structure,
; check_security and check_hardening (run here with output suppressed).
;
; CI gate: the process exits 2 when any HIGH or MEDIUM finding is present, so
; `elfcheck -t file && deploy` fails on dangerous binaries.  LOW/INFO findings
; are hardening-policy or informational and never change the exit code.
; ===========================================================================

; tri_finding - record and print one finding, in text or JSON form.
;   in: rsi = message cstr, al = severity (SEV_HIGH..SEV_INFO)
;   bumps the matching counter, then emits either "  [SEV]    message\n"
;   (text) or {"severity":"SEV","message":"..."} (when [tri_json] is set).
tri_finding:
    push rsi                    ; [rsp] = message
    cmp al, SEV_HIGH
    jne .tf_med
    inc qword [tri_high]
    lea rdx, [tri_lbl_high]
    lea rcx, [tri_sev_high]
    jmp .tf_emit
.tf_med:
    cmp al, SEV_MED
    jne .tf_low
    inc qword [tri_med]
    lea rdx, [tri_lbl_med]
    lea rcx, [tri_sev_med]
    jmp .tf_emit
.tf_low:
    cmp al, SEV_LOW
    jne .tf_info
    inc qword [tri_low]
    lea rdx, [tri_lbl_low]
    lea rcx, [tri_sev_low]
    jmp .tf_emit
.tf_info:
    inc qword [tri_info]
    lea rdx, [tri_lbl_info]
    lea rcx, [tri_sev_info]
.tf_emit:
    cmp byte [tri_json], 0
    jne .tf_json
    ; --- text: "  [SEV]    message\n" ---
    mov rsi, rdx
    call print_cstr            ; severity label
    pop rsi
    call print_cstr            ; message
    lea rsi, [nl]
    call print_cstr
    ret
.tf_json:
    ; --- JSON: {"severity":"SEV","message":"..."} into the findings array ---
    push rcx                    ; [rsp] = severity name, [rsp+8] = message
    cmp byte [tri_first], 0
    je .tf_j_comma
    mov byte [tri_first], 0
    jmp .tf_j_obj
.tf_j_comma:
    PRINT j_comma
.tf_j_obj:
    PRINT j_lbrace
    PRINT jk_severity
    pop rsi                     ; severity name
    call jname
    PRINT j_comma
    PRINT jk_message
    pop rsi                     ; message (our own safe ASCII strings)
    call jname
    PRINT j_rbrace
    ret

; scan_dangerous_imports - set [tri_cap_seen] bits for watched undefined
;   (imported) .dynsym symbols. Silent; call before emitting findings.
;   Static binaries / no .dynsym -> no bits set. fd in r12 (preserved).
scan_dangerous_imports:
    mov byte [tri_cap_seen], 0
    mov eax, 11                 ; SHT_DYNSYM
    call find_section
    cmp rax, -1
    je .sdi_ret
    mov rax, [shdr + SH_OFFSET]
    mov [dsym_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [dsym_size], rax
    mov rax, [shdr + SH_ENTSIZE]
    mov [dsym_ent], rax
    mov eax, dword [shdr + SH_LINK]
    call load_dynstr           ; .dynstr via sh_link
    push rbx
    push r13
    push r14
    push r15
    mov rcx, [dsym_ent]
    test rcx, rcx
    jz .sdi_pop                ; no entry size -> nothing to iterate
    mov rax, [dsym_size]
    xor rdx, rdx
    div rcx                    ; rax = count = size / entsize
    mov r14, rax
    xor r13, r13               ; symbol index
.sdi_loop:
    cmp r13, r14
    jae .sdi_pop
    mov rax, r13
    mul qword [dsym_ent]
    add rax, [dsym_off]
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [syment]
    mov rdx, 24
    mov rax, SYS_READ
    syscall
    cmp rax, 24
    jl .sdi_pop
    movzx eax, word [syment + 6]   ; st_shndx
    test eax, eax
    jnz .sdi_next              ; defined here -> not an import
    mov eax, dword [syment]       ; st_name
    test eax, eax
    jz .sdi_next
    call dynstr_name_ptr      ; rsi -> imported name
    lea r15, [tri_imp_tbl]
.sdi_tbl:
    mov rdi, [r15]            ; watch name ptr (0 terminates table)
    test rdi, rdi
    jz .sdi_next
    call streq               ; al=1 if equal; rsi/rdi preserved
    test al, al
    jnz .sdi_hit
    add r15, 16
    jmp .sdi_tbl
.sdi_hit:
    mov cl, [r15 + 8]        ; capability bit for this entry
    or [tri_cap_seen], cl
.sdi_next:
    inc r13
    jmp .sdi_loop
.sdi_pop:
    pop r15
    pop r14
    pop r13
    pop rbx
.sdi_ret:
    ret

; run_triage - gather facts silently, emit severity-ranked findings + summary.
; Text form by default; a JSON object when [tri_json] is set. The CI gate
; ([tri_fail]) is computed identically in both forms.
run_triage:
    cmp byte [tri_json], 0
    jne .rt_json_open
    PRINT tri_title
    jmp .rt_gather
.rt_json_open:
    PRINT j_lbrace             ; { "triage": { "findings": [
    PRINT jk_triage
    PRINT j_lbrace
    PRINT jk_findings
    PRINT j_lbrack
    mov byte [tri_first], 1
.rt_gather:

    ; --- reuse the existing analysers, output suppressed ---
    mov byte [silent], 1
    call validate_structure    ; -> [issues]
    call check_security        ; -> sec_wx, sec_wxsect, sec_stack, sec_entry_ok
    call check_hardening       ; -> hd_* (incl. hd_textrel)
    mov byte [silent], 0

    mov qword [tri_high], 0
    mov qword [tri_med], 0
    mov qword [tri_low], 0
    mov qword [tri_info], 0
    mov byte [tri_fail], 0
    call scan_dangerous_imports   ; -> [tri_cap_seen]
    call scan_packed_sections     ; -> [tri_packed]

    ; ------------------------------------------------------------------ HIGH
    cmp qword [issues], 0
    je .t_wxseg
    FINDING SEV_HIGH, tri_m_struct
.t_wxseg:
    cmp qword [sec_wx], 0
    je .t_xstack
    FINDING SEV_HIGH, tri_m_wxseg
.t_xstack:
    cmp byte [sec_stack], 2
    jne .t_textrel
    FINDING SEV_HIGH, tri_m_xstack
.t_textrel:
    cmp byte [hd_textrel], 0
    je .t_wxsect
    FINDING SEV_HIGH, tri_m_textrel

    ; ----------------------------------------------------------------- MEDIUM
.t_wxsect:
    cmp qword [sec_wxsect], 0
    je .t_entry
    FINDING SEV_MED, tri_m_wxsect
.t_entry:
    mov rax, [ehdr + E_ENTRY]
    test rax, rax
    jz .t_imp_gets             ; no entry address (e.g. a DSO): nothing to check
    cmp byte [sec_entry_ok], 0
    jne .t_imp_gets
    FINDING SEV_MED, tri_m_entry
.t_imp_gets:
    test byte [tri_cap_seen], CAP_GETS
    jz .t_packed
    FINDING SEV_MED, tri_mi_gets
.t_packed:
    cmp byte [tri_packed], 0
    je .t_noshdr
    FINDING SEV_MED, tri_m_packed

    ; -------------------------------------------------------------------- LOW
.t_noshdr:
    movzx eax, word [ehdr + E_SHNUM]
    test eax, eax
    jnz .t_relro
    FINDING SEV_LOW, tri_m_noshdr
.t_relro:
    cmp byte [hd_relro_seg], 0
    jne .t_relro_partial
    FINDING SEV_LOW, tri_m_norelro
    jmp .t_pie
.t_relro_partial:
    cmp byte [hd_bindnow], 0
    jne .t_pie
    FINDING SEV_LOW, tri_m_partrelro
.t_pie:
    movzx eax, word [ehdr + E_TYPE]
    cmp eax, ET_EXEC
    jne .t_canary
    FINDING SEV_LOW, tri_m_nopie
.t_canary:
    cmp byte [hd_canary], 0
    jne .t_cet
    FINDING SEV_LOW, tri_m_nocanary
.t_cet:
    ; CET is "fully enabled" only when the GNU property is present and both the
    ; IBT and SHSTK feature bits are set; otherwise flag it once.
    cmp byte [hd_cet_seen], 0
    je .t_cet_flag
    mov eax, dword [hd_cet_flags]
    and eax, (GNU_PROPERTY_X86_FEATURE_1_IBT | GNU_PROPERTY_X86_FEATURE_1_SHSTK)
    cmp eax, (GNU_PROPERTY_X86_FEATURE_1_IBT | GNU_PROPERTY_X86_FEATURE_1_SHSTK)
    je .t_rpath
.t_cet_flag:
    FINDING SEV_LOW, tri_m_nocet
.t_rpath:
    cmp qword [hd_rpath_off], -1
    je .t_runpath
    FINDING SEV_LOW, tri_m_rpath
.t_runpath:
    cmp qword [hd_runpath_off], -1
    je .t_imp_exec
    FINDING SEV_LOW, tri_m_runpath
.t_imp_exec:
    test byte [tri_cap_seen], CAP_EXEC
    jz .t_stripped
    FINDING SEV_LOW, tri_mi_exec

    ; ------------------------------------------------------------------- INFO
.t_stripped:
    movzx eax, word [ehdr + E_SHNUM]
    test eax, eax
    jz .t_imp_net              ; no sections at all -> already a LOW finding
    mov eax, 2                 ; SHT_SYMTAB
    call find_section          ; overwrites [shdr] (scratch at this point)
    cmp rax, -1
    jne .t_imp_net
    FINDING SEV_INFO, tri_m_stripped
.t_imp_net:
    test byte [tri_cap_seen], CAP_NET
    jz .t_summary
    FINDING SEV_INFO, tri_mi_net

    ; ---------------------------------------------------------------- summary
.t_summary:
    ; CI gate: any HIGH or MEDIUM finding trips the non-zero exit code
    ; (computed for both the text and JSON forms).
    mov rax, [tri_high]
    add rax, [tri_med]
    test rax, rax
    jz .t_nogate
    mov byte [tri_fail], 1
.t_nogate:
    cmp byte [tri_json], 0
    jne .t_json_summary
    ; --- text summary ---
    mov rax, [tri_high]
    add rax, [tri_med]
    add rax, [tri_low]
    add rax, [tri_info]
    test rax, rax
    jnz .t_report
    PRINT tri_clean
    ret
.t_report:
    PRINT tri_sum_pre
    mov rax, [tri_high]
    call print_dec
    PRINT tri_sum_high
    mov rax, [tri_med]
    call print_dec
    PRINT tri_sum_med
    mov rax, [tri_low]
    call print_dec
    PRINT tri_sum_low
    mov rax, [tri_info]
    call print_dec
    PRINT tri_sum_info
    ret
.t_json_summary:
    PRINT j_rbrack             ; close "findings":[ ... ]
    PRINT j_comma
    PRINT jk_summary
    PRINT j_lbrace
    PRINT jk_high
    mov rax, [tri_high]
    call print_dec
    PRINT j_comma
    PRINT jk_medium
    mov rax, [tri_med]
    call print_dec
    PRINT j_comma
    PRINT jk_low
    mov rax, [tri_low]
    call print_dec
    PRINT j_comma
    PRINT jk_info
    mov rax, [tri_info]
    call print_dec
    PRINT j_rbrace             ; close "summary":{ ... }
    PRINT j_comma
    PRINT jk_gate
    cmp byte [tri_fail], 0
    jne .t_js_gate_true
    PRINT j_false
    jmp .t_js_close
.t_js_gate_true:
    PRINT j_true
.t_js_close:
    PRINT j_rbrace             ; close "triage":{ ... }
    PRINT j_rbrace             ; close outer { ... }
    PRINT nl
    ret
