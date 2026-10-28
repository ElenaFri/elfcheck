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

; tri_finding - record and print one finding.
;   in: rsi = message cstr, al = severity (SEV_HIGH..SEV_INFO)
;   bumps the matching counter, then prints "  [SEV]    message\n".
tri_finding:
    push rsi
    cmp al, SEV_HIGH
    jne .tf_med
    inc qword [tri_high]
    lea rsi, [tri_lbl_high]
    jmp .tf_emit
.tf_med:
    cmp al, SEV_MED
    jne .tf_low
    inc qword [tri_med]
    lea rsi, [tri_lbl_med]
    jmp .tf_emit
.tf_low:
    cmp al, SEV_LOW
    jne .tf_info
    inc qword [tri_low]
    lea rsi, [tri_lbl_low]
    jmp .tf_emit
.tf_info:
    inc qword [tri_info]
    lea rsi, [tri_lbl_info]
.tf_emit:
    call print_cstr            ; severity label
    pop rsi
    call print_cstr            ; message
    lea rsi, [nl]
    call print_cstr
    ret

; run_triage - gather facts silently, emit severity-ranked findings + summary.
run_triage:
    PRINT tri_title

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
    jz .t_noshdr               ; no entry address (e.g. a DSO): nothing to check
    cmp byte [sec_entry_ok], 0
    jne .t_noshdr
    FINDING SEV_MED, tri_m_entry

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
    je .t_stripped
    FINDING SEV_LOW, tri_m_runpath

    ; ------------------------------------------------------------------- INFO
.t_stripped:
    movzx eax, word [ehdr + E_SHNUM]
    test eax, eax
    jz .t_summary              ; no sections at all -> already a LOW finding
    mov eax, 2                 ; SHT_SYMTAB
    call find_section          ; overwrites [shdr] (scratch at this point)
    cmp rax, -1
    jne .t_summary
    FINDING SEV_INFO, tri_m_stripped

    ; ---------------------------------------------------------------- summary
.t_summary:
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
    ; CI gate: any HIGH or MEDIUM finding trips the non-zero exit code.
    mov rax, [tri_high]
    add rax, [tri_med]
    test rax, rax
    jz .t_ret
    mov byte [tri_fail], 1
.t_ret:
    ret
