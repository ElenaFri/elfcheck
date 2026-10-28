section .text
    global _start

_start:
    ; --- parse arguments: output-mode and section-filter flags + one path ---
    mov r8, [rsp]              ; argc
    lea r9, [rsp + 8]         ; &argv[0]
    xor r10, r10              ; path pointer (NULL until found)
    mov byte [json_mode], 0
    mov byte [disasm_mode], 0
    mov byte [triage_mode], 0
    mov byte [help_mode], 0
    mov byte [disasm_error], 0
    mov qword [function_name], 0
    mov byte [disasm_start_set], 0
    mov byte [disasm_count_set], 0
    mov qword [disasm_start_addr], 0
    mov qword [disasm_count], 0
    mov dword [filter_mask], 0
    mov rcx, 1               ; i = 1 (skip argv[0])
.arg_loop:
    cmp rcx, r8
    jae .args_done
    MODEARG opt_json,     json_mode
    MODEARG opt_disasm,   disasm_mode
    MODEARG opt_disasm_s, disasm_mode
    MODEARG opt_triage,   triage_mode
    MODEARG opt_triage_s, triage_mode
    MODEARG opt_help,     help_mode
    MODEARG opt_help_s,   help_mode
    mov rsi, [r9 + rcx*8]
    lea rdi, [opt_function]
    call streq
    test al, al
    jz .not_function_arg
    cmp qword [function_name], 0
    jne .usage
    inc rcx
    cmp rcx, r8
    jae .usage
    mov rax, [r9 + rcx*8]
    test rax, rax
    jz .usage
    mov [function_name], rax
    mov byte [disasm_mode], 1
    jmp .arg_next
.not_function_arg:
    mov rsi, [r9 + rcx*8]
    lea rdi, [opt_start_address]
    call streq
    test al, al
    jz .not_start_address
    cmp byte [disasm_start_set], 0
    jne .usage
    inc rcx
    cmp rcx, r8
    jae .usage
    mov rdi, [r9 + rcx*8]
    test rdi, rdi
    jz .usage
    cmp byte [rdi], '0'
    jne .parse_start_address
    mov al, [rdi + 1]
    cmp al, 'x'
    je .strip_address_prefix
    cmp al, 'X'
    jne .parse_start_address
.strip_address_prefix:
    add rdi, 2
.parse_start_address:
    mov esi, 16
    call parse_unsigned
    jc .usage
    mov [disasm_start_addr], rax
    mov byte [disasm_start_set], 1
    mov byte [disasm_mode], 1
    jmp .arg_next
.not_start_address:
    mov rsi, [r9 + rcx*8]
    lea rdi, [opt_count]
    call streq
    test al, al
    jz .not_count
    cmp byte [disasm_count_set], 0
    jne .usage
    inc rcx
    cmp rcx, r8
    jae .usage
    mov rdi, [r9 + rcx*8]
    test rdi, rdi
    jz .usage
    mov esi, 10
    call parse_unsigned
    jc .usage
    test rax, rax
    jz .usage
    mov [disasm_count], rax
    mov byte [disasm_count_set], 1
    mov byte [disasm_mode], 1
    jmp .arg_next
.not_count:
    FILTARG opt_header,    FILT_HEADER
    FILTARG opt_segments,  FILT_SEGMENTS
    FILTARG opt_sections,  FILT_SECTIONS
    FILTARG opt_validate,  FILT_VALIDATE
    FILTARG opt_security,  FILT_SECURITY
    FILTARG opt_dynamic,   FILT_DYNAMIC
    FILTARG opt_hardening, FILT_HARDENING
    FILTARG opt_symbols,   FILT_SYMBOLS
    FILTARG opt_relocs,    FILT_RELOCS
    FILTARG opt_notes,     FILT_NOTES
    mov rsi, [r9 + rcx*8]
    test r10, r10            ; otherwise it's the path (only one allowed)
    jnz .usage
    mov r10, rsi
.arg_next:
    inc rcx
    jmp .arg_loop
.args_done:
    cmp byte [help_mode], 0  ; --help prints usage to stdout and exits 0
    je .need_path
    lea rsi, [usage_msg]
    mov rdx, usage_len
    call print_str
    xor edi, edi
    jmp .exit
.need_path:
    test r10, r10            ; a path is required
    jz .usage

    mov rdi, r10             ; open(path, O_RDONLY)
    mov rax, SYS_OPEN
    xor esi, esi              ; O_RDONLY
    xor edx, edx
    syscall
    test rax, rax
    js .open_error
    mov r12, rax              ; save fd

    mov rdi, r12             ; read the header
    mov rax, SYS_READ
    lea rsi, [ehdr]
    mov rdx, EHDR_SIZE
    syscall
    cmp rax, 4               ; need at least the 4 magic bytes
    jl .read_error
    mov [nread], rax

    mov eax, dword [ehdr]      ; validate magic
    cmp eax, dword [elf_magic]
    jne .invalid

    cmp qword [nread], EHDR_SIZE
    jl .truncated

    cmp byte [ehdr + EI_CLASS], ELFCLASS64
    jne .unsupported
    cmp byte [ehdr + EI_DATA], ELFDATA2LSB
    jne .unsupported

    cmp byte [disasm_mode], 0
    jne .emit_disasm
    cmp byte [triage_mode], 0
    jne .emit_triage
    cmp byte [json_mode], 0
    jne .emit_json
    ; --- text report: run only the selected sections (empty mask = all) ---
    mov eax, dword [filter_mask]
    test eax, eax
    jnz .mask_set
    mov eax, FILT_DEFAULT
.mask_set:
    mov [eff_mask], eax
    test dword [eff_mask], FILT_HEADER
    jz .f_seg
    call print_header
.f_seg:
    test dword [eff_mask], FILT_SEGMENTS
    jz .f_sec
    call print_program_headers ; reads segments via fd in r12
.f_sec:
    test dword [eff_mask], FILT_SECTIONS
    jz .f_symbols
    call print_section_headers ; reads sections via fd in r12
.f_symbols:
    test dword [eff_mask], FILT_SYMBOLS
    jz .f_relocs
    call print_symbol_tables
.f_relocs:
    test dword [eff_mask], FILT_RELOCS
    jz .f_val
    call print_relocation_tables
.f_val:
    ; validation always runs so the exit code stays meaningful; it prints
    ; only when selected, otherwise it just counts [issues] silently.
    test dword [eff_mask], FILT_VALIDATE
    jnz .f_val_loud
    mov byte [silent], 1
    call validate_structure
    mov byte [silent], 0
    jmp .f_sec_check
.f_val_loud:
    call validate_structure    ; sanity-check offsets, counts [issues]
.f_sec_check:
    test dword [eff_mask], FILT_SECURITY
    jz .f_dyn
    call check_security        ; segment perms + stack exec, counts [warnings]
.f_dyn:
    test dword [eff_mask], FILT_DYNAMIC
    jz .f_hard
    call analyze_dynamic       ; needed libraries + imported symbols
.f_hard:
    test dword [eff_mask], FILT_HARDENING
    jz .f_notes
    call check_hardening       ; exploit-mitigation posture (checksec-style)
.f_notes:
    test dword [eff_mask], FILT_NOTES
    jz .after_output
    call print_notes           ; decode ELF notes (build-id, ABI tag, properties)
    jmp .after_output
.emit_json:
    call print_json            ; emits everything + counts [issues]
    jmp .after_output
.emit_triage:
    call run_triage            ; severity-ranked anomaly scan; sets [tri_fail]
    jmp .after_triage
.emit_disasm:
    call disassemble           ; disassemble .text; leaves [issues] at 0
.after_output:
    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall
    xor edi, edi            ; exit 0 if no structural issues...
    cmp byte [disasm_error], 0
    jne .disasm_failed
    cmp qword [issues], 0
    je .exit
    mov edi, 2              ; ...else exit 2
    jmp .exit
.disasm_failed:
    mov edi, 1
    jmp .exit

.after_triage:
    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall
    xor edi, edi            ; exit 0 unless a HIGH/MED finding tripped the gate
    cmp byte [tri_fail], 0
    je .exit
    mov edi, 2
    jmp .exit

.invalid:
    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall
    lea rsi, [invalid_msg]
    mov rdx, invalid_len
    call print_stderr
    mov edi, 1
    jmp .exit

.unsupported:
    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall
    lea rsi, [unsupported_msg]
    mov rdx, unsupported_len
    call print_stderr
    mov edi, 1
    jmp .exit

.truncated:
    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall
    lea rsi, [trunc_msg]
    mov rdx, trunc_len
    call print_stderr
    mov edi, 1
    jmp .exit

.usage:
    lea rsi, [usage_msg]
    mov rdx, usage_len
    call print_stderr
    mov edi, 1
    jmp .exit

.open_error:
    lea rsi, [open_err_msg]
    mov rdx, open_err_len
    call print_stderr
    mov edi, 1
    jmp .exit

.read_error:
    mov rdi, r12
    mov rax, SYS_CLOSE
    syscall
    lea rsi, [read_err_msg]
    mov rdx, read_err_len
    call print_stderr
    mov edi, 1
    jmp .exit

.exit:
    mov rax, SYS_EXIT
    syscall

; ---------------------------------------------------------------------------
