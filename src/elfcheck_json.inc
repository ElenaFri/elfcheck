; print_json - emit the whole analysis as a single-line JSON object.
; Minified on purpose (pipe through `jq` for pretty-printing).
; ---------------------------------------------------------------------------
print_json:
    PRINT j_lbrace
    call json_header
    PRINT j_comma
    call json_phdrs
    PRINT j_comma
    call json_shdrs
    PRINT j_comma
    call json_symbol_tables
    PRINT j_comma
    call json_relocation_tables
    PRINT j_comma
    call json_validation
    PRINT j_comma
    call json_security
    PRINT j_comma
    call json_dynamic
    PRINT j_comma
    call json_notes
    PRINT j_comma
    call json_hardening
    PRINT j_rbrace
    PRINT nl
    ret

; json_header - "header":{ ...fields... }
json_header:
    PRINT jk_header
    PRINT j_lbrace

    PRINT jk_class
    movzx eax, byte [ehdr + EI_CLASS]
    call class_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_data
    movzx eax, byte [ehdr + EI_DATA]
    call data_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_osabi
    movzx eax, byte [ehdr + EI_OSABI]
    call osabi_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_type
    movzx eax, word [ehdr + E_TYPE]
    call type_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_machine
    movzx eax, word [ehdr + E_MACHINE]
    call machine_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_entry
    mov rax, [ehdr + E_ENTRY]
    call jhex
    PRINT j_comma

    PRINT jk_phoff
    mov rax, [ehdr + E_PHOFF]
    call print_dec
    PRINT j_comma

    PRINT jk_shoff
    mov rax, [ehdr + E_SHOFF]
    call print_dec
    PRINT j_comma

    PRINT jk_flags
    mov eax, dword [ehdr + E_FLAGS]
    call jhex
    PRINT j_comma

    PRINT jk_ehsize
    movzx eax, word [ehdr + E_EHSIZE]
    call print_dec
    PRINT j_comma

    PRINT jk_phentsize
    movzx eax, word [ehdr + E_PHENTSIZE]
    call print_dec
    PRINT j_comma

    PRINT jk_phnum
    movzx eax, word [ehdr + E_PHNUM]
    call print_dec
    PRINT j_comma

    PRINT jk_shentsize
    movzx eax, word [ehdr + E_SHENTSIZE]
    call print_dec
    PRINT j_comma

    PRINT jk_shnum
    movzx eax, word [ehdr + E_SHNUM]
    call print_dec
    PRINT j_comma

    PRINT jk_shstrndx
    movzx eax, word [ehdr + E_SHSTRNDX]
    call print_dec

    PRINT j_rbrace
    ret

; json_phdrs - "program_headers":[ {..}, {..} ]
json_phdrs:
    PRINT jk_phdrs
    PRINT j_lbrack
    movzx r14d, word [ehdr + E_PHNUM]
    xor r13, r13
.jp_loop:
    cmp r13, r14
    jae .jp_done
    movzx eax, word [ehdr + E_PHENTSIZE]
    imul rax, r13
    add rax, [ehdr + E_PHOFF]
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [phdr]
    mov rdx, PHDR_SIZE
    mov rax, SYS_READ
    syscall
    cmp rax, PHDR_SIZE
    jl .jp_done
    test r13, r13
    jz .jp_nocomma
    PRINT j_comma
.jp_nocomma:
    call json_one_phdr
    inc r13
    jmp .jp_loop
.jp_done:
    PRINT j_rbrack
    ret

json_one_phdr:
    PRINT j_lbrace
    PRINT jk_index
    mov rax, r13
    call print_dec
    PRINT j_comma
    PRINT jk_type
    mov eax, dword [phdr + P_TYPE]
    call phdr_type_name
    mov rsi, rax
    call jname
    PRINT j_comma
    PRINT jk_flags
    mov eax, dword [phdr + P_FLAGS]
    call build_flags
    lea rsi, [flagbuf]
    call jname
    PRINT j_comma
    PRINT jk_offset
    mov rax, [phdr + P_OFFSET]
    call jhex
    PRINT j_comma
    PRINT jk_vaddr
    mov rax, [phdr + P_VADDR]
    call jhex
    PRINT j_comma
    PRINT jk_filesz
    mov rax, [phdr + P_FILESZ]
    call jhex
    PRINT j_comma
    PRINT jk_memsz
    mov rax, [phdr + P_MEMSZ]
    call jhex
    PRINT j_comma
    PRINT jk_align
    mov rax, [phdr + P_ALIGN]
    call jhex
    PRINT j_rbrace
    ret

; json_shdrs - "section_headers":[ {..}, {..} ]
json_shdrs:
    PRINT jk_shdrs
    PRINT j_lbrack
    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .js_done
    call load_shstrtab
    xor r13, r13
.js_loop:
    cmp r13, r14
    jae .js_done
    movzx eax, word [ehdr + E_SHENTSIZE]
    imul rax, r13
    add rax, [ehdr + E_SHOFF]
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [shdr]
    mov rdx, SHDR_SIZE
    mov rax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jl .js_done
    test r13, r13
    jz .js_nocomma
    PRINT j_comma
.js_nocomma:
    call json_one_shdr
    inc r13
    jmp .js_loop
.js_done:
    PRINT j_rbrack
    ret

json_one_shdr:
    PRINT j_lbrace
    PRINT jk_index
    mov rax, r13
    call print_dec
    PRINT j_comma
    PRINT jk_name
    call section_name_ptr       ; rsi -> name
    call jstr                   ; escaped (name comes from the file)
    PRINT j_comma
    PRINT jk_type
    mov eax, dword [shdr + SH_TYPE]
    call shdr_type_name
    mov rsi, rax
    call jname
    PRINT j_comma
    PRINT jk_flags
    mov rax, [shdr + SH_FLAGS]
    call build_sh_flags
    lea rsi, [shflagbuf]
    call jname
    PRINT j_comma
    PRINT jk_addr
    mov rax, [shdr + SH_ADDR]
    call jhex
    PRINT j_comma
    PRINT jk_offset
    mov rax, [shdr + SH_OFFSET]
    call jhex
    PRINT j_comma
    PRINT jk_size
    mov rax, [shdr + SH_SIZE]
    call jhex
    PRINT j_comma
    PRINT jk_addralign
    mov rax, [shdr + SH_ADDRALIGN]
    call jhex
    PRINT j_rbrace
    ret

; json_validation - "validation":{"issues":N,"valid":bool}
; Runs validate_structure silently to count issues.
json_validation:
    PRINT jk_validation
    PRINT j_lbrace
    mov byte [silent], 1
    call validate_structure
    mov byte [silent], 0
    PRINT jk_issues
    mov rax, [issues]
    call print_dec
    PRINT j_comma
    PRINT jk_valid
    cmp qword [issues], 0
    jne .jv_invalid
    PRINT j_true
    jmp .jv_close
.jv_invalid:
    PRINT j_false
.jv_close:
    PRINT j_rbrace
    ret

; json_security - "security":{"gnu_stack":"...","executable_stack":bool,
;                 "wx_segments":N,"wx_sections":N,"entry_in_exec":bool,
;                 "has_section_headers":bool,"warnings":N}
; Runs check_security silently to populate the counters.
json_security:
    PRINT jk_security
    PRINT j_lbrace
    mov byte [silent], 1
    call check_security
    mov byte [silent], 0
    PRINT jk_gnustack
    cmp byte [sec_stack], 2
    je .js_exec
    cmp byte [sec_stack], 1
    je .js_noexec
    lea rsi, [jv_st_absent]
    jmp .js_stname
.js_noexec:
    lea rsi, [jv_st_noexec]
    jmp .js_stname
.js_exec:
    lea rsi, [jv_st_exec]
.js_stname:
    call jname
    PRINT j_comma
    PRINT jk_execstack
    cmp byte [sec_stack], 2
    jne .js_nx
    PRINT j_true
    jmp .js_wx
.js_nx:
    PRINT j_false
.js_wx:
    PRINT j_comma
    PRINT jk_wxseg
    mov rax, [sec_wx]
    call print_dec
    PRINT j_comma
    PRINT jk_wxsect
    mov rax, [sec_wxsect]
    call print_dec
    PRINT j_comma
    PRINT jk_entryok
    ; entry_in_exec: true if entry==0 (no code address) or it lies in exec seg
    cmp qword [ehdr + E_ENTRY], 0
    je .js_entry_true
    cmp byte [sec_entry_ok], 1
    je .js_entry_true
    PRINT j_false
    jmp .js_shdr
.js_entry_true:
    PRINT j_true
.js_shdr:
    PRINT j_comma
    PRINT jk_hasshdr
    cmp word [ehdr + E_SHNUM], 0
    je .js_noshdr
    PRINT j_true
    jmp .js_warn
.js_noshdr:
    PRINT j_false
.js_warn:
    PRINT j_comma
    PRINT jk_warnings
    mov rax, [warnings]
    call print_dec
    PRINT j_rbrace
    ret

; json_dynamic - "dynamic":{"static":bool,"needed":[..],"imports":[..]}
json_dynamic:
    PRINT jk_dynamic
    PRINT j_lbrace
    PRINT jk_static
    cmp word [ehdr + E_SHNUM], 0
    je .jd_static
    mov eax, 6                  ; SHT_DYNAMIC
    call find_section
    cmp rax, -1
    jne .jd_dynamic
.jd_static:
    PRINT j_true
    PRINT j_comma
    PRINT jk_needed
    PRINT j_lbrack
    PRINT j_rbrack
    PRINT j_comma
    PRINT jk_imports
    PRINT j_lbrack
    PRINT j_rbrack
    PRINT j_rbrace
    ret
.jd_dynamic:
    PRINT j_false
    mov rax, [shdr + SH_OFFSET]
    mov [dyn_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [dyn_size], rax
    mov eax, dword [shdr + SH_LINK]
    mov [dyn_link], eax
    mov eax, dword [dyn_link]
    call load_dynstr
    PRINT j_comma
    PRINT jk_needed
    PRINT j_lbrack
    call json_needed_arr
    PRINT j_rbrack
    PRINT j_comma
    PRINT jk_imports
    PRINT j_lbrack
    mov eax, 11                 ; SHT_DYNSYM
    call find_section
    cmp rax, -1
    je .jd_noimp
    mov rax, [shdr + SH_OFFSET]
    mov [dsym_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [dsym_size], rax
    mov rax, [shdr + SH_ENTSIZE]
    mov [dsym_ent], rax
    mov eax, dword [shdr + SH_LINK]
    mov [dsym_link], eax
    mov eax, dword [dsym_link]
    call load_dynstr
    call json_imports_arr
.jd_noimp:
    PRINT j_rbrack
    PRINT j_rbrace
    ret

; json_needed_arr - emit comma-separated JSON strings for DT_NEEDED libs
json_needed_arr:
    mov r14, [dyn_size]
    shr r14, 4
    xor r13, r13
    xor rbx, rbx
.jn_loop:
    cmp r13, r14
    jae .jn_done
    mov rax, r13
    shl rax, 4
    add rax, [dyn_off]
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [dynent]
    mov rdx, 16
    mov rax, SYS_READ
    syscall
    cmp rax, 16
    jl .jn_done
    mov rax, [dynent]
    test rax, rax
    jz .jn_done
    cmp rax, 1                  ; DT_NEEDED
    jne .jn_next
    test rbx, rbx
    jz .jn_nocomma
    PRINT j_comma
.jn_nocomma:
    mov rax, [dynent + 8]
    call dynstr_name_ptr
    call jstr
    inc rbx
.jn_next:
    inc r13
    jmp .jn_loop
.jn_done:
    ret

; json_imports_arr - emit comma-separated JSON strings for imported symbols
json_imports_arr:
    mov rcx, [dsym_ent]
    test rcx, rcx
    jz .ji_done
    mov rax, [dsym_size]
    xor rdx, rdx
    div rcx
    mov r14, rax
    xor r13, r13
    xor rbx, rbx
.ji_loop:
    cmp r13, r14
    jae .ji_done
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
    jl .ji_done
    movzx eax, word [syment + 6]
    test eax, eax
    jnz .ji_next
    mov eax, dword [syment]
    test eax, eax
    jz .ji_next
    test rbx, rbx
    jz .ji_nocomma
    PRINT j_comma
.ji_nocomma:
    mov eax, dword [syment]
    call dynstr_name_ptr
    call jstr
    inc rbx
.ji_next:
    inc r13
    jmp .ji_loop
.ji_done:
    ret

; json_hardening - "hardening":{"relro":..,"stack_canary":bool,"nx":..,
;                 "pie":..,"ibt":..,"shstk":..,"rpath":str|null,
;                 "runpath":str|null,"fortify":N}
; Runs check_hardening silently to populate the hd_* fields.
json_hardening:
    PRINT jk_hardening
    PRINT j_lbrace
    mov byte [silent], 1
    call check_hardening
    mov byte [silent], 0
    ; --- relro ---
    PRINT jk_relro
    cmp byte [hd_relro_seg], 0
    je .jh_relro_none
    cmp byte [hd_bindnow], 0
    jne .jh_relro_full
    lea rsi, [jv_partial]
    jmp .jh_relro_emit
.jh_relro_full:
    lea rsi, [jv_full]
    jmp .jh_relro_emit
.jh_relro_none:
    lea rsi, [jv_none]
.jh_relro_emit:
    call jname
    PRINT j_comma
    ; --- stack_canary ---
    PRINT jk_canary
    cmp byte [hd_canary], 0
    jne .jh_can_true
    PRINT j_false
    jmp .jh_nx
.jh_can_true:
    PRINT j_true
.jh_nx:
    PRINT j_comma
    ; --- nx ---
    PRINT jk_nx
    cmp byte [hd_stack], 2
    je .jh_nx_dis
    cmp byte [hd_stack], 0
    je .jh_nx_unk
    lea rsi, [jv_enabled]
    jmp .jh_nx_emit
.jh_nx_dis:
    lea rsi, [jv_disabled]
    jmp .jh_nx_emit
.jh_nx_unk:
    lea rsi, [jv_unknown]
.jh_nx_emit:
    call jname
    PRINT j_comma
    ; --- pie ---
    PRINT jk_pie
    movzx eax, word [ehdr + E_TYPE]
    cmp eax, ET_EXEC
    je .jh_pie_dis
    cmp eax, ET_DYN
    jne .jh_pie_na
    cmp byte [hd_interp], 0
    je .jh_pie_dso
    lea rsi, [jv_enabled]
    jmp .jh_pie_emit
.jh_pie_dis:
    lea rsi, [jv_disabled]
    jmp .jh_pie_emit
.jh_pie_dso:
    lea rsi, [jv_dso]
    jmp .jh_pie_emit
.jh_pie_na:
    lea rsi, [jv_na]
.jh_pie_emit:
    call jname
    PRINT j_comma
    ; --- CET properties ---
    PRINT jk_ibt
    mov ecx, GNU_PROPERTY_X86_FEATURE_1_IBT
    call json_cet_status
    PRINT j_comma
    PRINT jk_shstk
    mov ecx, GNU_PROPERTY_X86_FEATURE_1_SHSTK
    call json_cet_status
    PRINT j_comma
    ; --- rpath ---
    PRINT jk_rpath
    cmp qword [hd_rpath_off], -1
    je .jh_rpath_null
    mov rax, [hd_rpath_off]
    call dynstr_name_ptr
    call jstr
    jmp .jh_runpath
.jh_rpath_null:
    PRINT j_null
.jh_runpath:
    PRINT j_comma
    ; --- runpath ---
    PRINT jk_runpath
    cmp qword [hd_runpath_off], -1
    je .jh_runpath_null
    mov rax, [hd_runpath_off]
    call dynstr_name_ptr
    call jstr
    jmp .jh_fortify
.jh_runpath_null:
    PRINT j_null
.jh_fortify:
    PRINT j_comma
    ; --- fortify ---
    PRINT jk_fortify
    mov rax, [hd_fortify]
    call print_dec
    PRINT j_rbrace
    ret

; json_cet_status - emit a tri-state CET property value; feature bit in ecx.
json_cet_status:
    cmp byte [hd_cet_seen], 0
    je .jcs_unknown
    test dword [hd_cet_flags], ecx
    jz .jcs_disabled
    lea rsi, [jv_enabled]
    jmp .jcs_emit
.jcs_disabled:
    lea rsi, [jv_disabled]
    jmp .jcs_emit
.jcs_unknown:
    lea rsi, [jv_unknown]
.jcs_emit:
    call jname
    ret

; json_notes - "notes":[{"owner":..,"type":N,"descsz":N,"desc":..},..]
; Reuses the shared note walker with a JSON-emitting per-record handler.
json_notes:
    PRINT jk_notes
    PRINT j_lbrack
    mov qword [note_count], 0
    mov qword [note_ranges_seen], 0
    lea rax, [note_handler_json]
    mov [note_handler], rax
    mov rdi, r12
    xor esi, esi
    mov edx, SEEK_END
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .jnt_close
    mov [filesize], rax
    call notes_scan_sections
    cmp qword [note_ranges_seen], 0
    jne .jnt_close
    call notes_scan_segments
.jnt_close:
    PRINT j_rbrack
    ret

; note_handler_json - per-record handler: emit one JSON object for the note.
note_handler_json:
    push rbx
    cmp qword [note_count], 0
    je .njson_first
    PRINT j_comma
.njson_first:
    inc qword [note_count]
    call note_read_owner
    call note_stage_desc
    PRINT j_lbrace
    PRINT jk_owner
    lea rsi, [note_owner]
    call jstr
    PRINT j_comma
    PRINT jk_type
    mov eax, dword [note_type]
    call print_dec
    PRINT j_comma
    PRINT jk_descsz
    mov rax, [note_desc_size]
    call print_dec
    cmp dword [note_owner], 0x00554e47   ; "GNU\0"
    jne .njson_end
    mov eax, [note_type]
    cmp eax, NT_GNU_BUILD_ID
    je .njson_buildid
    cmp eax, NT_GNU_ABI_TAG
    je .njson_abi
    jmp .njson_end
.njson_buildid:
    PRINT j_comma
    PRINT jk_desc
    PRINT j_quote
    xor ebx, ebx
.njb_loop:
    cmp rbx, [note_desc_staged]
    jae .njb_done
    lea rdx, [note_desc_buf]
    mov al, [rdx + rbx]
    call print_byte_hex
    inc rbx
    jmp .njb_loop
.njb_done:
    PRINT j_quote
    jmp .njson_end
.njson_abi:
    cmp qword [note_desc_staged], 16
    jb .njson_end
    PRINT j_comma
    PRINT jk_desc
    PRINT j_quote
    mov eax, dword [note_desc_buf]
    call note_print_os
    mov eax, dword [note_desc_buf + 4]
    call print_dec
    PRINT note_dot
    mov eax, dword [note_desc_buf + 8]
    call print_dec
    PRINT note_dot
    mov eax, dword [note_desc_buf + 12]
    call print_dec
    PRINT j_quote
.njson_end:
    PRINT j_rbrace
    pop rbx
    ret

; ---------------------------------------------------------------------------
; jname - print rsi as a JSON string, no escaping (safe enum/flag text only)
; ---------------------------------------------------------------------------
jname:                     ; in: rsi = cstr
    push rsi
    PRINT j_quote
    pop rsi
    call print_cstr
    PRINT j_quote
    ret

; ---------------------------------------------------------------------------
; jstr - print rsi as JSON, escaping quotes, controls and non-ASCII bytes
; ---------------------------------------------------------------------------
jstr:                      ; in: rsi = cstr
    push rsi
    PRINT j_quote
    pop rsi
    call json_escape
    PRINT j_quote
    ret

; ---------------------------------------------------------------------------
; jhex - print rax as a JSON string holding its "0x.." hex form
; ---------------------------------------------------------------------------
jhex:                      ; in: rax = value
    push rax
    PRINT j_quote
    pop rax
    call print_hex
    PRINT j_quote
    ret

; ---------------------------------------------------------------------------
; json_escape - escape JSON specials and non-ASCII bytes from file strings.
; ---------------------------------------------------------------------------
json_escape:               ; in: rsi = cstr
    push rbx
    mov rbx, rsi
.je_loop:
    movzx eax, byte [rbx]
    test al, al
    jz .je_done
    cmp al, 34                 ; "
    je .je_quote
    cmp al, 92                 ; backslash
    je .je_bslash
    cmp al, 0x20               ; control char
    jb .je_ctrl
    cmp al, 0x7f               ; escape non-ASCII bytes as \u00XX
    ja .je_ctrl
    mov [jbuf], al             ; ordinary ASCII byte
    lea rsi, [jbuf]
    mov rdx, 1
    call print_str
    jmp .je_next
.je_quote:
    PRINT esc_quote
    jmp .je_next
.je_bslash:
    PRINT esc_bslash
    jmp .je_next
.je_ctrl:
    PRINT esc_u00              ; emit \u00 then two hex digits
    movzx eax, byte [rbx]
    mov edx, eax
    shr edx, 4
    and edx, 0xf
    mov al, dl
    call nibble_hex
    mov [jbuf], al
    movzx edx, byte [rbx]
    and edx, 0xf
    mov al, dl
    call nibble_hex
    mov [jbuf + 1], al
    lea rsi, [jbuf]
    mov rdx, 2
    call print_str
.je_next:
    inc rbx
    jmp .je_loop
.je_done:
    pop rbx
    ret

; nibble_hex - low nibble of al -> ascii hex char in al
nibble_hex:
    and al, 0xf
    cmp al, 10
    jb .nh_digit
    add al, 'a' - 10
    ret
.nh_digit:
    add al, '0'
    ret

