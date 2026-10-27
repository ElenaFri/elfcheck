; ===========================================================================
; Disassembler (x86-64, common integer subset).  Unknown bytes fall back to
; a single ".byte 0x.." so decoding always makes forward progress.
; ===========================================================================

; find_function_symbol - search SHT_SYMTAB first, then SHT_DYNSYM.
; Stores the first defined STT_FUNC matching [function_name].
find_function_symbol:
    push r13
    push r14
    mov rdi, r12
    xor esi, esi
    mov edx, SEEK_END
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .file_size_failed
    mov [filesize], rax
    mov byte [func_symbol_seen], 0
    mov byte [func_symbol_found], 0
    mov dword [func_table_type], 2       ; SHT_SYMTAB
    call .scan_type
    cmp byte [func_symbol_found], 0
    jne .done
    mov dword [func_table_type], 11      ; SHT_DYNSYM
    call .scan_type
.done:
    movzx eax, byte [func_symbol_found]
    pop r14
    pop r13
    ret
.file_size_failed:
    mov byte [func_symbol_seen], 0
    mov byte [func_symbol_found], 0
    xor eax, eax
    pop r14
    pop r13
    ret

.scan_type:
    movzx r14d, word [ehdr + E_SHNUM]
    xor r13d, r13d
.section_loop:
    cmp r13, r14
    jae .type_done
    movzx eax, word [ehdr + E_SHENTSIZE]
    cmp eax, SHDR_SIZE
    jb .type_done
    imul rax, r13
    jo .type_done
    add rax, [ehdr + E_SHOFF]
    jc .type_done
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .type_done
    mov rdi, r12
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    mov eax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jne .type_done
    mov eax, [func_table_type]
    cmp dword [shdr + SH_TYPE], eax
    jne .section_next
    mov rax, [shdr + SH_OFFSET]
    mov [func_table_offset], rax
    mov rax, [shdr + SH_SIZE]
    mov [func_table_size], rax
    mov rax, [shdr + SH_ENTSIZE]
    mov [func_table_entsize], rax
    mov eax, [shdr + SH_LINK]
    mov [func_table_link], eax
    call .scan_table
    cmp byte [func_symbol_found], 0
    jne .type_done
.section_next:
    inc r13
    jmp .section_loop
.type_done:
    ret

.scan_table:
    cmp qword [func_table_entsize], 24
    jb .table_done
    cmp qword [func_table_size], 0
    je .table_done
    mov rax, [func_table_offset]
    add rax, [func_table_size]
    jc .table_done
    cmp rax, [filesize]
    ja .table_done
    mov rax, [func_table_size]
    xor edx, edx
    div qword [func_table_entsize]
    test rdx, rdx
    jnz .table_done
    mov [func_table_count], rax
    mov eax, [func_table_link]
    test eax, eax
    jz .table_done
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .table_done
    mov qword [dynstr_len], 0
    call load_dynstr
    cmp dword [shdr + SH_TYPE], 3 ; SHT_STRTAB
    jne .table_done
    cmp qword [dynstr_len], 0
    je .table_done
    mov rax, [func_table_offset]
    mov [func_table_current], rax
.symbol_loop:
    cmp qword [func_table_count], 0
    je .table_done
    mov rdi, r12
    mov rsi, [func_table_current]
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .table_done
    mov rdi, r12
    lea rsi, [syment]
    mov edx, 24
    mov eax, SYS_READ
    syscall
    cmp rax, 24
    jne .table_done
    mov eax, [syment]
    cmp rax, [dynstr_len]
    jae .symbol_next
    call dynstr_name_ptr
    mov rdi, [function_name]
    call streq
    test al, al
    jz .symbol_next
    mov al, [syment + 4]
    and al, 0x0f
    cmp al, 2                       ; STT_FUNC
    jne .symbol_next
    mov byte [func_symbol_seen], 1
    movzx eax, word [syment + 6]    ; st_shndx
    test eax, eax                   ; skip undefined imports
    jz .symbol_next
    mov [func_symbol_shndx], eax
    mov rax, [syment + 8]
    mov [func_symbol_value], rax
    mov rax, [syment + 16]
    mov [func_symbol_size], rax
    mov byte [func_symbol_found], 1
    jmp .table_done
.symbol_next:
    mov rax, [func_table_current]
    add rax, [func_table_entsize]
    jc .table_done
    mov [func_table_current], rax
    dec qword [func_table_count]
    jmp .symbol_loop
.table_done:
    ret

; select_function_range - turn the matching symbol into a bounded file range.
;   out: eax = 1 on success, 0 if the symbol cannot be safely disassembled.
select_function_range:
    call find_function_symbol
    test eax, eax
    jz .sfr_bad
    cmp qword [func_symbol_size], 0
    je .sfr_bad
    mov eax, [func_symbol_shndx]
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .sfr_bad
    movzx ecx, word [ehdr + E_SHENTSIZE]
    cmp ecx, SHDR_SIZE
    jb .sfr_bad
    imul rax, rcx
    jo .sfr_bad
    add rax, [ehdr + E_SHOFF]
    jc .sfr_bad
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .sfr_bad
    mov rdi, r12
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    mov eax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jne .sfr_bad
    cmp dword [shdr + SH_TYPE], 1 ; SHT_PROGBITS
    jne .sfr_bad
    test qword [shdr + SH_FLAGS], SHF_EXECINSTR
    jz .sfr_bad
    call section_name_ptr
    mov [sel_name], rsi
    mov rax, [shdr + SH_SIZE]
    mov [func_section_size], rax
    mov rax, [shdr + SH_OFFSET]
    mov [sel_off], rax
    add rax, [func_section_size]
    jc .sfr_bad
    cmp rax, [filesize]
    ja .sfr_bad
    movzx eax, word [ehdr + E_TYPE]
    cmp eax, ET_REL
    je .sfr_relocatable
    cmp eax, ET_EXEC
    je .sfr_address
    cmp eax, ET_DYN
    jne .sfr_bad
.sfr_address:
    mov rax, [func_symbol_value]
    cmp rax, [shdr + SH_ADDR]
    jb .sfr_bad
    sub rax, [shdr + SH_ADDR]
    mov [func_delta], rax
    mov rax, [func_symbol_value]
    mov [sel_addr], rax
    jmp .sfr_check_bounds
.sfr_relocatable:
    mov rax, [func_symbol_value]
    mov [func_delta], rax
    add rax, [shdr + SH_ADDR]
    jc .sfr_bad
    mov [sel_addr], rax
.sfr_check_bounds:
    mov rax, [func_delta]
    add rax, [func_symbol_size]
    jc .sfr_bad
    cmp rax, [func_section_size]
    ja .sfr_bad
    mov rax, [sel_off]
    add rax, [func_delta]
    jc .sfr_bad
    mov [sel_off], rax
    mov rax, [func_symbol_size]
    mov [sel_size], rax
    mov eax, [func_symbol_shndx]
    mov [sel_index], rax
    mov eax, 1
    ret
.sfr_bad:
    xor eax, eax
    ret

; print_stderr_cstr - write a NUL-terminated string to stderr.
print_stderr_cstr:
    xor edx, edx
.psc_len:
    cmp byte [rsi + rdx], 0
    je .psc_write
    inc rdx
    jmp .psc_len
.psc_write:
    call print_stderr
    ret

; Build a bounded cache so relative branch annotation requires no file I/O
; while instructions are being decoded.
build_disasm_symbol_cache:
    push rbx
    push r13
    push r14
    mov qword [func_cache_count], 0
    mov qword [func_cache_names_len], 0
    movzx eax, word [ehdr + E_TYPE]
    cmp eax, ET_EXEC
    je .bsc_size
    cmp eax, ET_DYN
    jne .bsc_done
.bsc_size:
    mov rdi, r12
    xor esi, esi
    mov edx, SEEK_END
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .bsc_done
    mov [filesize], rax
    mov dword [func_table_type], 2       ; SHT_SYMTAB first
    call .load_table
    mov dword [func_table_type], 11      ; then SHT_DYNSYM
    call .load_table
.bsc_done:
    pop r14
    pop r13
    pop rbx
    ret

.load_table:
    mov eax, [func_table_type]
    call find_section
    cmp rax, -1
    je .lt_done
    mov rax, [shdr + SH_OFFSET]
    mov [func_table_offset], rax
    mov rax, [shdr + SH_SIZE]
    mov [func_table_size], rax
    mov rax, [shdr + SH_ENTSIZE]
    mov [func_table_entsize], rax
    mov eax, [shdr + SH_LINK]
    mov [func_table_link], eax
    cmp qword [func_table_entsize], 24
    jb .lt_done
    cmp qword [func_table_size], 0
    je .lt_done
    mov rax, [func_table_offset]
    add rax, [func_table_size]
    jc .lt_done
    cmp rax, [filesize]
    ja .lt_done
    mov rax, [func_table_size]
    xor edx, edx
    div qword [func_table_entsize]
    test rdx, rdx
    jnz .lt_done
    mov [func_table_count], rax
    mov eax, [func_table_link]
    test eax, eax
    jz .lt_done
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .lt_done
    mov qword [dynstr_len], 0
    call load_dynstr
    cmp dword [shdr + SH_TYPE], 3 ; SHT_STRTAB
    jne .lt_done
    cmp qword [dynstr_len], 0
    je .lt_done
    mov rax, [func_table_offset]
    mov [func_table_current], rax
.symbol_loop:
    cmp qword [func_table_count], 0
    je .lt_done
    cmp qword [func_cache_count], FUNC_CACHE_CAP
    jae .lt_done
    mov rdi, r12
    mov rsi, [func_table_current]
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .lt_done
    mov rdi, r12
    lea rsi, [syment]
    mov edx, 24
    mov eax, SYS_READ
    syscall
    cmp rax, 24
    jne .lt_done
    movzx eax, byte [syment + 4]
    and eax, 0x0f
    cmp eax, 2                       ; STT_FUNC
    jne .symbol_next
    movzx eax, word [syment + 6]     ; defined section index
    test eax, eax
    jz .symbol_next
    cmp eax, 0xffff                  ; SHN_XINDEX is not resolved here
    je .symbol_next
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .symbol_next
    mov eax, [syment]
    cmp rax, [dynstr_len]
    jae .symbol_next
    call dynstr_name_ptr
    cmp byte [rsi], 0
    je .symbol_next
    mov rbx, rsi
    xor ecx, ecx
.name_length:
    cmp byte [rbx + rcx], 0
    je .name_ready
    inc ecx
    jmp .name_length
.name_ready:
    mov rdx, [func_cache_names_len]
    mov r8, DYNSTR_CAP
    sub r8, rdx
    mov r9, rcx
    inc r9                           ; include NUL terminator
    cmp r9, r8
    ja .symbol_next
    mov rax, [func_cache_count]
    mov rdx, [syment + 8]            ; st_value
    lea r10, [func_cache_values]
    mov [r10 + rax*8], rdx
    mov rdx, [func_cache_names_len]
    lea r10, [func_cache_name_offsets]
    mov [r10 + rax*8], rdx
    lea rdi, [func_cache_names]
    add rdi, rdx
    mov rsi, rbx
    mov rcx, r9
    rep movsb
    add qword [func_cache_names_len], r9
    inc qword [func_cache_count]
.symbol_next:
    mov rax, [func_table_current]
    add rax, [func_table_entsize]
    jc .lt_done
    mov [func_table_current], rax
    dec qword [func_table_count]
    jmp .symbol_loop
.lt_done:
    ret

; lookup_function_name - in rax = target address; out rsi = name or NULL.
lookup_function_name:
    mov rdx, rax
    xor ecx, ecx
.lfn_loop:
    cmp rcx, [func_cache_count]
    jae .lfn_none
    lea r8, [func_cache_values]
    mov rax, [r8 + rcx*8]
    cmp rax, rdx
    je .lfn_found
    inc rcx
    jmp .lfn_loop
.lfn_found:
    lea r8, [func_cache_name_offsets]
    mov rax, [r8 + rcx*8]
    lea rsi, [func_cache_names]
    add rsi, rax
    ret
.lfn_none:
    xor esi, esi
    ret

; Build a bounded cache of PC-relative relocations for the selected ET_REL section.
build_disasm_relocation_cache:
    push rbx
    push r13
    push r14
    push r15
    mov qword [reloc_cache_count], 0
    mov qword [reloc_cache_names_len], 0
    mov dword [reloc_cache_match_type], 0
    cmp word [ehdr + E_TYPE], ET_REL
    jne .bdrc_done
    cmp word [ehdr + E_MACHINE], 62
    jne .bdrc_done

    mov rdi, r12
    xor esi, esi
    mov edx, SEEK_END
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .bdrc_done
    mov [filesize], rax
    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .bdrc_done
    movzx ecx, word [ehdr + E_SHENTSIZE]
    cmp ecx, SHDR_SIZE
    jb .bdrc_done
    mov rax, r14
    mul rcx
    test rdx, rdx
    jnz .bdrc_done
    add rax, [ehdr + E_SHOFF]
    jc .bdrc_done
    cmp rax, [filesize]
    ja .bdrc_done

    xor r13d, r13d
.bdrc_scan:
    cmp r13, r14
    jae .bdrc_done
    movzx eax, word [ehdr + E_SHENTSIZE]
    imul rax, r13
    add rax, [ehdr + E_SHOFF]
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .bdrc_done
    mov rdi, r12
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    mov eax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jl .bdrc_done

    mov eax, dword [shdr + SH_TYPE]
    cmp eax, 4                    ; SHT_RELA
    je .bdrc_rela
    cmp eax, 9                    ; SHT_REL
    jne .bdrc_next_section
    mov dword [rel_table_type], 9
    jmp .bdrc_match_target
.bdrc_rela:
    mov dword [rel_table_type], 4
.bdrc_match_target:
    mov eax, dword [shdr + SH_INFO]
    cmp rax, [sel_index]
    jne .bdrc_next_section
    mov rax, [shdr + SH_OFFSET]
    mov [rel_table_offset], rax
    mov rax, [shdr + SH_SIZE]
    mov [rel_table_size], rax
    mov rax, [shdr + SH_ENTSIZE]
    mov [rel_table_entsize], rax
    mov eax, dword [shdr + SH_LINK]
    mov [rel_table_link], eax
    mov qword [rel_entry_count], 0

    mov rax, [rel_table_entsize]
    cmp dword [rel_table_type], 4
    jne .bdrc_min_rel
    cmp rax, 24                  ; Elf64_Rela
    jb .bdrc_next_section
    jmp .bdrc_check_range
.bdrc_min_rel:
    cmp rax, 16                  ; Elf64_Rel
    jb .bdrc_next_section
.bdrc_check_range:
    mov rax, [rel_table_offset]
    add rax, [rel_table_size]
    jc .bdrc_next_section
    cmp rax, [filesize]
    ja .bdrc_next_section
    mov rax, [rel_table_size]
    xor edx, edx
    div qword [rel_table_entsize]
    test rdx, rdx
    jnz .bdrc_next_section
    mov [rel_entry_count], rax

    call load_relocation_symbols
    cmp byte [rel_symtab_valid], 1
    jne .bdrc_next_section
    cmp byte [rel_str_valid], 1
    jne .bdrc_next_section
    mov qword [rel_entry_index], 0
.bdrc_entry_loop:
    mov rax, [rel_entry_index]
    cmp rax, [rel_entry_count]
    jae .bdrc_next_section
    mul qword [rel_table_entsize]
    test rdx, rdx
    jnz .bdrc_next_section
    add rax, [rel_table_offset]
    jc .bdrc_next_section
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .bdrc_next_section
    mov qword [rel_entry + 16], 0
    mov rdi, r12
    lea rsi, [rel_entry]
    mov edx, 16
    cmp dword [rel_table_type], 4
    jne .bdrc_read_entry
    mov edx, 24
.bdrc_read_entry:
    mov eax, SYS_READ
    syscall
    cmp dword [rel_table_type], 4
    jne .bdrc_read_rel
    cmp rax, 24
    jl .bdrc_next_section
    jmp .bdrc_parse_entry
.bdrc_read_rel:
    cmp rax, 16
    jl .bdrc_next_section
.bdrc_parse_entry:
    mov rax, [rel_entry]
    mov [rel_offset], rax
    mov rax, [rel_entry + 8]
    mov edx, eax
    mov [rel_type_id], edx
    cmp edx, 2                   ; R_X86_64_PC32
    je .bdrc_supported_type
    cmp edx, 4                   ; R_X86_64_PLT32
    je .bdrc_supported_type
    cmp edx, 15                  ; R_X86_64_PC8
    je .bdrc_supported_type
    cmp edx, 9                   ; R_X86_64_GOTPCREL
    je .bdrc_supported_type
    cmp edx, 41                  ; R_X86_64_GOTPCRELX
    je .bdrc_supported_type
    cmp edx, 42                  ; R_X86_64_REX_GOTPCRELX
    jne .bdrc_entry_next
.bdrc_supported_type:
    shr rax, 32
    mov [rel_symbol_index], eax
    call resolve_relocation_symbol
    cmp byte [rel_symbol_state], 1
    jne .bdrc_entry_next
    mov rsi, [rel_symbol_name]
    cmp byte [rsi], 0
    je .bdrc_entry_next
    mov rbx, rsi
    xor ecx, ecx
.bdrc_name_len:
    cmp byte [rbx + rcx], 0
    je .bdrc_name_ready
    inc ecx
    jmp .bdrc_name_len
.bdrc_name_ready:
    lea r9, [rcx + 1]
    mov r8, DYNSTR_CAP
    sub r8, [reloc_cache_names_len]
    cmp r9, r8
    ja .bdrc_entry_next
    mov rax, [reloc_cache_count]
    cmp rax, RELOC_CACHE_CAP
    jae .bdrc_done
    mov rdx, [rel_offset]
    lea r8, [reloc_cache_offsets]
    mov [r8 + rax*8], rdx
    mov edx, [rel_type_id]
    lea r8, [reloc_cache_type_ids]
    mov [r8 + rax*4], edx
    mov rdx, [reloc_cache_names_len]
    lea r8, [reloc_cache_name_offsets]
    mov [r8 + rax*8], rdx
    lea rdi, [reloc_cache_names]
    add rdi, rdx
    mov rsi, rbx
    mov rcx, r9
    rep movsb
    add [reloc_cache_names_len], r9
    inc qword [reloc_cache_count]
.bdrc_entry_next:
    inc qword [rel_entry_index]
    jmp .bdrc_entry_loop
.bdrc_next_section:
    inc r13
    jmp .bdrc_scan
.bdrc_done:
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; disassemble - locate .text (PROGBITS + EXECINSTR), load it, decode & print.
disassemble:
    mov qword [issues], 0
    mov qword [sel_off], -1
    mov qword [sel_index], 0
    mov qword [text_trunc], 0
    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jnz .have_sections
    cmp qword [function_name], 0
    jne .function_not_found
    jmp .none
.have_sections:
    call load_shstrtab
    call build_disasm_symbol_cache
    cmp qword [function_name], 0
    jne .select_function
    xor r13, r13
.find_loop:
    cmp r13, r14
    jae .find_done
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
    jl .find_done
    mov eax, dword [shdr + SH_TYPE]     ; PROGBITS?
    cmp eax, 1
    jne .next
    test byte [shdr + SH_FLAGS], 0x4    ; SHF_EXECINSTR?
    jz .next
    call section_name_ptr               ; rsi -> name
    push rsi
    lea rdi, [name_text]
    call streq
    pop rsi
    test al, al
    jnz .pick
    cmp qword [sel_off], -1             ; else remember first exec section
    jne .next
    call .save_sel
    jmp .next
.pick:
    call .save_sel
    jmp .find_done
.next:
    inc r13
    jmp .find_loop
.save_sel:
    mov rax, [shdr + SH_OFFSET]
    mov [sel_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [sel_size], rax
    mov rax, [shdr + SH_ADDR]
    mov [sel_addr], rax
    mov [sel_name], rsi
    mov [sel_index], r13
    ret
.find_done:
    cmp qword [sel_off], -1
    je .none
    jmp .load_selected
.select_function:
    call select_function_range
    test eax, eax
    jnz .load_selected
    cmp byte [func_symbol_seen], 0
    jne .function_range_error
.function_not_found:
    lea rsi, [func_err_not_found]
    call print_stderr_cstr
    mov rsi, [function_name]
    call print_stderr_cstr
    lea rsi, [nl]
    call print_stderr_cstr
    mov byte [disasm_error], 1
    ret
.function_range_error:
    lea rsi, [func_err_no_range]
    call print_stderr_cstr
    mov rsi, [function_name]
    call print_stderr_cstr
    lea rsi, [nl]
    call print_stderr_cstr
    mov byte [disasm_error], 1
    ret
.load_selected:
    call build_disasm_relocation_cache
    mov rax, [sel_size]                 ; clamp to TEXT_CAP
    cmp rax, TEXT_CAP
    jbe .szok
    mov rax, TEXT_CAP
    mov qword [text_trunc], 1
.szok:
    mov [text_len], rax
    mov rax, [sel_addr]
    mov [text_vaddr], rax
    mov rdi, r12                        ; read section bytes into textbuf
    mov rsi, [sel_off]
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
    test rax, rax
    js .selected_read_failed
    mov rdi, r12
    lea rsi, [textbuf]
    mov rdx, [text_len]
    mov rax, SYS_READ
    syscall
    test rax, rax
    js .selected_read_failed
    cmp qword [function_name], 0
    je .read_complete
    cmp rax, [text_len]
    jne .function_range_error
.read_complete:
    mov [text_len], rax
    cmp qword [function_name], 0
    je .print_section_title
    PRINT dis_function_title
    mov rsi, [function_name]
    call print_cstr
    PRINT dis_function_section
    mov rsi, [sel_name]
    call print_cstr
    PRINT dis_colon_nl
    jmp .title_done
.print_section_title:
    PRINT dis_title                     ; header line
    mov rsi, [sel_name]
    call print_cstr
    PRINT dis_colon_nl
.title_done:
    lea rax, [textbuf]                  ; set up decode loop
    mov [d_cur], rax
    add rax, [text_len]
    mov [d_end], rax
.dloop:
    mov rax, [d_cur]
    cmp rax, [d_end]
    jae .dend
    lea rdx, [textbuf]                  ; vaddr of this instruction
    sub rax, rdx
    add rax, [text_vaddr]
    mov [d_vaddr], rax
    call decode_one
    jmp .dloop
.dend:
    cmp qword [text_trunc], 0
    je .ret
    PRINT dis_trunc_note
.ret:
    ret
.selected_read_failed:
    cmp qword [function_name], 0
    jne .function_range_error
    jmp .none
.none:
    lea rsi, [dis_nosect]
    mov rdx, dis_nosect_len
    call print_stderr
    ret

; --- byte stream access over textbuf (cursor in [d_cur], limit [d_end]) ---
peek8:                         ; out: al = byte (0 at end, sets d_trunc)
    mov rsi, [d_cur]
    cmp rsi, [d_end]
    jb .ok
    mov byte [d_trunc], 1
    xor eax, eax
    ret
.ok:
    movzx eax, byte [rsi]
    ret

adv8:
    inc qword [d_cur]
    ret

fetch8:                        ; out: al = next byte, cursor advanced
    call peek8
    push rax
    call adv8
    pop rax
    ret

; read_bytes_le - read cl (1..8) bytes little-endian; out rax zero-extended.
read_bytes_le:
    push rbx
    push r12
    xor eax, eax
    xor r12d, r12d             ; shift amount
    movzx ebx, cl              ; remaining count
.loop:
    test ebx, ebx
    jz .done
    push rax
    call fetch8
    movzx edx, al
    pop rax
    mov cl, r12b
    shl rdx, cl
    or rax, rdx
    add r12d, 8
    dec ebx
    jmp .loop
.done:
    pop r12
    pop rbx
    ret

; sign_extend - in: rax value, cl = width (1,2,4) -> rax sign-extended.
sign_extend:
    cmp cl, 1
    je .s1
    cmp cl, 2
    je .s2
    cmp cl, 4
    je .s4
    ret
.s1:
    movsx rax, al
    ret
.s2:
    movsx rax, ax
    ret
.s4:
    movsxd rax, eax
    ret

set_imm_vsize:                 ; imm width: 2 with 0x66, else 4
    cmp byte [d_opsize], 1
    je .w
    mov byte [d_imm_size], 4
    ret
.w:
    mov byte [d_imm_size], 2
    ret

read_disp:
    movzx ecx, byte [d_disp_size]
    test ecx, ecx
    jz .none
    call read_bytes_le
    movzx ecx, byte [d_disp_size]
    call sign_extend
    mov [d_disp], rax
.none:
    ret

read_imm:
    movzx ecx, byte [d_imm_size]
    test ecx, ecx
    jz .none
    call read_bytes_le
    cmp byte [d_imm_signed], 1
    jne .store
    movzx ecx, byte [d_imm_size]
    call sign_extend
.store:
    mov [d_imm], rax
.none:
    ret

set_disp_by_mod:
    cmp byte [d_mod], 1
    je .d8
    cmp byte [d_mod], 2
    je .d32
    mov byte [d_disp_size], 0
    ret
.d8:
    mov byte [d_disp_size], 1
    ret
.d32:
    mov byte [d_disp_size], 4
    ret

; parse_modrm - consume ModR/M (+ SIB) and set the operand fields.
parse_modrm:
    call fetch8
    mov [d_modrm], al
    mov cl, al                 ; mod
    shr cl, 6
    mov [d_mod], cl
    mov dl, al                 ; reg + REX.R
    shr dl, 3
    and dl, 7
    test byte [d_rex], 4
    jz .r1
    or dl, 8
.r1:
    mov [d_reg], dl
    mov bl, al                 ; rm low 3 bits
    and bl, 7
    cmp byte [d_mod], 3
    jne .mem
    mov dl, bl                 ; register-direct rm
    test byte [d_rex], 1
    jz .r2
    or dl, 8
.r2:
    mov [d_rm], dl
    mov byte [d_mem], 0
    ret
.mem:
    mov byte [d_mem], 1
    cmp bl, 4
    je .sib
    cmp byte [d_mod], 0
    jne .base
    cmp bl, 5
    jne .base
    mov byte [d_riprel], 1     ; RIP-relative
    mov byte [d_disp_size], 4
    ret
.base:
    mov dl, bl
    test byte [d_rex], 1
    jz .r3
    or dl, 8
.r3:
    mov [d_base], dl
    mov byte [d_no_index], 1
    call set_disp_by_mod
    ret
.sib:
    call fetch8
    mov [d_sibv], al
    mov cl, al                 ; scale
    shr cl, 6
    mov [d_scale], cl
    mov dl, al                 ; index
    shr dl, 3
    and dl, 7
    cmp dl, 4
    jne .have_index
    test byte [d_rex], 2
    jnz .have_index
    mov byte [d_no_index], 1
    jmp .sbase
.have_index:
    test byte [d_rex], 2
    jz .hi
    or dl, 8
.hi:
    mov [d_index], dl
.sbase:
    mov al, [d_sibv]
    and al, 7
    cmp al, 5
    jne .sreg
    cmp byte [d_mod], 0
    jne .sreg5
    mov byte [d_no_base], 1    ; mod==0, base==101 -> disp32 only
    mov byte [d_disp_size], 4
    ret
.sreg5:
    mov dl, 5
    test byte [d_rex], 1
    jz .sr5
    or dl, 8
.sr5:
    mov [d_base], dl
    call set_disp_by_mod
    ret
.sreg:
    mov dl, al
    test byte [d_rex], 1
    jz .sr
    or dl, 8
.sr:
    mov [d_base], dl
    call set_disp_by_mod
    ret

reset_decode_state:
    lea rdi, [dstate]
    mov ecx, dstate_end - dstate
    xor eax, eax
    rep stosb
    ret

; cur_opnd_size - out: cl = operand size in bytes.
cur_opnd_size:
    cmp byte [d_vec], 0
    jne .vector
    cmp byte [d_byte], 1
    je .s1
    test byte [d_rex], 8       ; REX.W
    jnz .s8
    cmp byte [d_opsize], 1
    je .s2
    cmp byte [d_defsize8], 1
    je .s8
    mov cl, 4
    ret
.s8:
    mov cl, 8
    ret
.s2:
    mov cl, 2
    ret
.s1:
    mov cl, 1
    ret
.vector:
    mov cl, [d_vec_size]
    ret

; emit_reg - al = index (0-15), cl = size; prints register name
emit_reg:
    push rbx
    movzx ebx, al
    cmp byte [d_vec], 0
    je .gpr
    cmp byte [d_vec], 1
    jne .ymm
    lea rax, [regs_xmm]
    mov rsi, [rax + rbx*8]
    jmp .out
.ymm:
    lea rax, [regs_ymm]
    mov rsi, [rax + rbx*8]
    jmp .out
.gpr:
    cmp cl, 8
    je .q
    cmp cl, 4
    je .d
    cmp cl, 2
    je .w
    test byte [d_hasrex], 1    ; byte register
    jnz .brex
    cmp ebx, 4
    jb .brex
    cmp ebx, 8
    jae .brex
    lea rax, [regs8h]
    mov rsi, [rax + rbx*8]
    jmp .out
.brex:
    lea rax, [regs8]
    mov rsi, [rax + rbx*8]
    jmp .out
.q:
    lea rax, [regs64]
    mov rsi, [rax + rbx*8]
    jmp .out
.d:
    lea rax, [regs32]
    mov rsi, [rax + rbx*8]
    jmp .out
.w:
    lea rax, [regs16]
    mov rsi, [rax + rbx*8]
.out:
    call print_cstr
    pop rbx
    ret

; emit_addr_reg - emit a GPR used as a memory base/index, even for vector ops.
emit_addr_reg:
    cmp byte [d_vec], 0
    je .gpr
    mov dl, [d_vec]
    mov byte [d_vec], 0
    push rdx
    call emit_reg
    pop rdx
    mov [d_vec], dl
    ret
.gpr:
    jmp emit_reg

; emit_disp_signed - print "+0x.." or "-0x.." for [d_disp]
emit_disp_signed:
    mov rax, [d_disp]
    test rax, rax
    js .neg
    PRINT dis_plus
    mov rax, [d_disp]
    call print_hex
    ret
.neg:
    PRINT dis_minus
    mov rax, [d_disp]
    neg rax
    call print_hex
    ret

; emit_rm - cl = size; print the ModR/M r/m operand (register or memory)
emit_rm:
    cmp byte [d_mem], 0
    jne .mem
    mov al, [d_rm]
    jmp emit_reg               ; tail call, cl already set
.mem:
    cmp byte [d_nosize], 1
    je .nokw
    push rcx                   ; size keyword
    movzx eax, cl
    cmp al, 1
    je .k0
    cmp al, 2
    je .k1
    cmp al, 4
    je .k2
    cmp al, 16
    je .k4
    cmp al, 32
    je .k5
    mov edx, 3
    jmp .kk
.k0:
    xor edx, edx
    jmp .kk
.k1:
    mov edx, 1
    jmp .kk
.k2:
    mov edx, 2
    jmp .kk
.k4:
    mov edx, 4
    jmp .kk
.k5:
    mov edx, 5
.kk:
    lea rax, [sz_tbl]
    mov rsi, [rax + rdx*8]
    call print_cstr
    pop rcx
.nokw:
    PRINT dis_lbr
    cmp byte [d_riprel], 1
    jne .notrip
    PRINT dis_rip
    cmp word [ehdr + E_TYPE], ET_REL
    jne .rip_disp
    mov rax, [d_cur]
    sub rax, [d_start]
    add rax, [d_vaddr]
    movzx ecx, byte [d_imm_size]
    sub rax, rcx
    movzx ecx, byte [d_disp_size]
    sub rax, rcx
    call lookup_disasm_relocation
    test rsi, rsi
    jz .rip_disp
    push rsi
    PRINT dis_plus
    pop rsi
    call print_cstr
    jmp .close_reloc
.rip_disp:
    call emit_disp_signed
    jmp .close
.notrip:
    mov byte [first_printed], 0
    cmp byte [d_no_base], 1
    je .aftbase
    mov al, [d_base]
    push rcx
    mov cl, 8
    call emit_addr_reg
    pop rcx
    mov byte [first_printed], 1
.aftbase:
    cmp byte [d_no_index], 1
    je .aftindex
    cmp byte [first_printed], 1
    jne .noplus
    PRINT dis_plus
.noplus:
    mov al, [d_index]
    push rcx
    mov cl, 8
    call emit_addr_reg
    pop rcx
    PRINT dis_star
    movzx ecx, byte [d_scale]  ; scale = 1 << exponent
    mov eax, 1
    shl eax, cl
    mov rax, rax
    push rcx
    call print_dec
    pop rcx
    mov byte [first_printed], 1
.aftindex:
    movzx eax, byte [d_disp_size]
    test eax, eax
    jz .close
    cmp byte [first_printed], 1
    jne .displead
    call emit_disp_signed
    jmp .close
.displead:
    mov rax, [d_disp]
    call print_hex
.close:
    PRINT dis_rbr
    ret
.close_reloc:
    PRINT dis_rbr
    PRINT dis_reloc_open
    mov eax, [reloc_cache_match_type]
    call relocation_type_name
    mov rsi, rax
    call print_cstr
    PRINT dis_reloc_close
    ret

emit_imm:
    mov rax, [d_imm]
    call print_hex
    ret

; print_byte_hex - al -> two lowercase hex chars on stdout
print_byte_hex:
    push rax
    mov dl, al
    shr dl, 4
    mov al, dl
    call nibble_hex
    mov [bytebuf], al
    pop rax
    mov dl, al
    and dl, 0xf
    mov al, dl
    call nibble_hex
    mov [bytebuf + 1], al
    lea rsi, [bytebuf]
    mov rdx, 2
    call print_str
    ret

; lookup_disasm_relocation - in rax = relocation field offset;
;   out rsi = symbol name or NULL, type saved in reloc_cache_match_type.
lookup_disasm_relocation:
    mov rdx, rax
    xor ecx, ecx
.ldr_loop:
    cmp rcx, [reloc_cache_count]
    jae .ldr_none
    lea r8, [reloc_cache_offsets]
    cmp [r8 + rcx*8], rdx
    je .ldr_found
    inc rcx
    jmp .ldr_loop
.ldr_found:
    lea r8, [reloc_cache_name_offsets]
    mov rax, [r8 + rcx*8]
    lea rsi, [reloc_cache_names]
    add rsi, rax
    lea r8, [reloc_cache_type_ids]
    mov eax, [r8 + rcx*4]
    mov [reloc_cache_match_type], eax
    ret
.ldr_none:
    xor esi, esi
    ret

; render_operands - print operands according to [d_style]
render_operands:
    movzx eax, byte [d_style]
    cmp eax, ST_RM_REG
    je .rm_reg
    cmp eax, ST_REG_RM
    je .reg_rm
    cmp eax, ST_RM_IMM
    je .rm_imm
    cmp eax, ST_RM
    je .rm
    cmp eax, ST_REG_IMM
    je .reg_imm
    cmp eax, ST_OREG
    je .oreg
    cmp eax, ST_ACC_IMM
    je .acc_imm
    cmp eax, ST_REL
    je .rel
    cmp eax, ST_IMM
    je .imm
    cmp eax, ST_RM_1
    je .rm_1
    cmp eax, ST_RM_CL
    je .rm_cl
    cmp eax, ST_REG_RM_B
    je .reg_rm_b
    cmp eax, ST_REG_RM_IMM
    je .reg_rm_imm
    cmp eax, ST_VEC3
    je .vec3
    ret
.rm_reg:
    call cur_opnd_size
    push rcx
    call emit_rm
    PRINT dis_comma
    pop rcx
    mov al, [d_reg]
    call emit_reg
    ret
.reg_rm:
    call cur_opnd_size
    push rcx
    mov al, [d_reg]
    call emit_reg
    PRINT dis_comma
    pop rcx
    call emit_rm
    ret
.rm_imm:
    call cur_opnd_size
    call emit_rm
    PRINT dis_comma
    call emit_imm
    ret
.rm:
    call cur_opnd_size
    call emit_rm
    ret
.reg_imm:
    call cur_opnd_size
    mov al, [d_reg]
    call emit_reg
    PRINT dis_comma
    call emit_imm
    ret
.oreg:
    call cur_opnd_size
    mov al, [d_reg]
    call emit_reg
    ret
.acc_imm:
    call cur_opnd_size
    xor al, al
    call emit_reg
    PRINT dis_comma
    call emit_imm
    ret
.rel:
    cmp word [ehdr + E_TYPE], ET_REL
    jne .rel_linked
    mov rax, [d_cur]
    sub rax, [d_start]
    add rax, [d_vaddr]
    movzx ecx, byte [d_imm_size]
    sub rax, rcx
    call lookup_disasm_relocation
    test rsi, rsi
    jz .rel_linked
    push rsi
    PRINT dis_sym_open
    pop rsi
    call print_cstr
    PRINT dis_sym_close
    PRINT dis_reloc_open
    mov eax, [reloc_cache_match_type]
    call relocation_type_name
    mov rsi, rax
    call print_cstr
    PRINT dis_reloc_close
    ret
.rel_linked:
    mov rax, [d_cur]
    sub rax, [d_start]
    add rax, [d_vaddr]
    add rax, [d_imm]
    mov [d_rel_target], rax
    call print_hex
    mov rax, [d_rel_target]
    call lookup_function_name
    test rsi, rsi
    jz .rel_done
    push rsi
    PRINT dis_sym_open
    pop rsi
    call print_cstr
    PRINT dis_sym_close
.rel_done:
    ret
.imm:
    call emit_imm
    ret
.rm_1:
    call cur_opnd_size
    call emit_rm
    PRINT dis_comma
    PRINT dis_one
    ret
.rm_cl:
    call cur_opnd_size
    call emit_rm
    PRINT dis_comma
    PRINT dis_cl
    ret
.reg_rm_b:
    call cur_opnd_size
    push rcx
    mov al, [d_reg]
    call emit_reg
    PRINT dis_comma
    pop rcx
    movzx ecx, byte [d_srcsz]
    call emit_rm
    ret
.reg_rm_imm:
    call cur_opnd_size
    push rcx
    mov al, [d_reg]
    call emit_reg
    PRINT dis_comma
    mov rcx, [rsp]
    call emit_rm
    PRINT dis_comma
    pop rcx
    call emit_imm
    ret
.vec3:
    call cur_opnd_size
    push rcx
    mov al, [d_reg]
    call emit_reg
    PRINT dis_comma
    mov rcx, [rsp]
    mov al, [d_vvvv]
    call emit_reg
    PRINT dis_comma
    pop rcx
    call emit_rm
    ret

; print_insn - render address, raw bytes and decoded instruction
print_insn:
    PRINT two_spaces
    mov rax, [d_vaddr]
    call print_hex
    PRINT dis_colon
    PRINT dis_space
    mov rbx, [d_start]
.bytes:
    cmp rbx, [d_cur]
    jae .bytes_done
    movzx eax, byte [rbx]
    push rbx
    call print_byte_hex
    PRINT dis_space
    pop rbx
    inc rbx
    jmp .bytes
.bytes_done:
    mov rax, [d_cur]           ; pad bytes column to 30
    sub rax, [d_start]
    imul rax, 3
    mov rdx, 30
    sub rdx, rax
    jle .mnem
    lea rsi, [dis_pad]
    call print_str
.mnem:
    mov rsi, [d_mnem]
    test rsi, rsi
    jz .done
    mov ecx, 7
    call print_cstr_pad
    PRINT dis_space
    call render_operands
.done:
    PRINT nl
    ret

; print_byte_insn - fallback line ".byte 0x.." for one unknown byte
print_byte_insn:
    PRINT two_spaces
    mov rax, [d_vaddr]
    call print_hex
    PRINT dis_colon
    PRINT dis_space
    mov rbx, [d_start]
    movzx eax, byte [rbx]
    call print_byte_hex
    PRINT dis_space
    mov rdx, 30 - 3
    lea rsi, [dis_pad]
    call print_str
    PRINT dis_byte_db
    PRINT dis_0x
    mov rbx, [d_start]
    movzx eax, byte [rbx]
    call print_byte_hex
    PRINT nl
    ret

; decode_one - decode and print a single instruction; out rax = length.
decode_one:
    call reset_decode_state
    mov rax, [d_cur]
    mov [d_start], rax
    call peek8
    cmp al, 0xc4
    je .vex
    cmp al, 0xc5
    je .vex
.pfx:
    call peek8
    cmp al, 0x66
    je .p66
    cmp al, 0x67
    je .p67
    cmp al, 0xf0
    je .pf0
    cmp al, 0xf2
    je .pf2
    cmp al, 0xf3
    je .pf3
    cmp al, 0x2e
    je .pseg
    cmp al, 0x36
    je .pseg
    cmp al, 0x3e
    je .pseg
    cmp al, 0x26
    je .pseg
    cmp al, 0x64
    je .pseg
    cmp al, 0x65
    je .pseg
    jmp .pfx_done
.p66:
    mov byte [d_opsize], 1
    call adv8
    jmp .pfx
.p67:
    mov byte [d_addrsz], 1
    call adv8
    jmp .pfx
.pf0:
    mov byte [d_lock], 1
    call adv8
    jmp .pfx
.pf2:
    mov byte [d_repne], 1
    call adv8
    jmp .pfx
.pf3:
    mov byte [d_rep], 1
    call adv8
    jmp .pfx
.pseg:
    mov [d_seg], al
    call adv8
    jmp .pfx
.pfx_done:
    call peek8                 ; REX?
    mov dl, al
    and dl, 0xf0
    cmp dl, 0x40
    jne .norex
    mov [d_rex], al
    mov byte [d_hasrex], 1
    call adv8
.norex:
    call fetch8                ; opcode
    cmp al, 0x0f
    je .two
    mov [d_op], al
    call decode_one_byte
    jmp .finish
.two:
    call fetch8
    mov [d_op], al
    call decode_two_byte
    jmp .finish
.vex:
    call fetch8                 ; C4 or C5
    cmp al, 0xc5
    je .vex2
    call fetch8                 ; VEX3: R/X/B and opcode map
    mov dl, al
    and al, 0x1f
    mov [d_vex_map], al
    cmp al, 1                    ; only the 0F opcode map is implemented
    jne .vex_unknown
    test dl, 0x80
    jnz .vex3_no_r
    or byte [d_rex], 4
.vex3_no_r:
    test dl, 0x40
    jnz .vex3_no_x
    or byte [d_rex], 2
.vex3_no_x:
    test dl, 0x20
    jnz .vex3_no_b
    or byte [d_rex], 1
.vex3_no_b:
    call fetch8                 ; VEX3: W/vvvv/L/pp
    mov dl, al
    test dl, 0x80               ; W=1 is outside the supported subset
    jnz .vex_unknown
    call decode_vex_payload
    cmp byte [d_style], 0xff
    je .finish
    jmp .vex_opcode
.vex2:
    mov byte [d_vex_map], 1    ; C5 implies the 0F map
    call fetch8                 ; VEX2: R/vvvv/L/pp
    mov dl, al
    test dl, 0x80
    jnz .vex2_no_r
    or byte [d_rex], 4
.vex2_no_r:
    call decode_vex_payload
    cmp byte [d_style], 0xff
    je .finish
.vex_opcode:
    cmp byte [d_trunc], 1
    je .finish
    call fetch8
    mov [d_op], al
    cmp byte [d_trunc], 1
    je .finish
    call decode_vex
    jmp .finish
.vex_unknown:
    mov byte [d_style], 0xff
.finish:
    cmp byte [d_trunc], 1
    je .as_byte
    cmp byte [d_style], 0xff
    je .as_byte
    call print_insn
    jmp .ret
.as_byte:
    mov rax, [d_start]
    inc rax
    mov [d_cur], rax
    call print_byte_insn
.ret:
    mov rax, [d_cur]
    sub rax, [d_start]
    ret

; decode_one_byte - in: al = opcode (also saved in [d_op]).
decode_one_byte:
    ; --- arithmetic block 0x00..0x3F (columns 0-5 of each group of 8) ---
    cmp al, 0x40
    jae .not_arith
    mov bl, al
    and bl, 7
    cmp bl, 6
    jae .not_arith
    mov cl, al
    shr cl, 3
    movzx ecx, cl
    lea rax, [grp_arith]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    cmp bl, 0
    je .ar0
    cmp bl, 1
    je .ar1
    cmp bl, 2
    je .ar2
    cmp bl, 3
    je .ar3
    cmp bl, 4
    je .ar4
    mov byte [d_style], ST_ACC_IMM   ; col 5: eAX, imm
    call set_imm_vsize
    call read_imm
    ret
.ar4:
    mov byte [d_byte], 1             ; col 4: AL, imm8
    mov byte [d_style], ST_ACC_IMM
    mov byte [d_imm_size], 1
    call read_imm
    ret
.ar0:
    mov byte [d_byte], 1
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.ar1:
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.ar2:
    mov byte [d_byte], 1
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.ar3:
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.not_arith:
    ; --- push/pop r64 (0x50..0x5F) ---
    cmp al, 0x50
    jb .c63
    cmp al, 0x5f
    ja .c63
    mov bl, al
    and bl, 7
    test byte [d_rex], 1
    jz .pp1
    or bl, 8
.pp1:
    mov [d_reg], bl
    mov byte [d_defsize8], 1
    mov byte [d_style], ST_OREG
    cmp al, 0x58
    jb .ppush
    lea rsi, [mn_pop]
    jmp .pp2
.ppush:
    lea rsi, [mn_push]
.pp2:
    mov [d_mnem], rsi
    ret
.c63:
    cmp al, 0x63                     ; movsxd r64, r/m32
    jne .c68
    lea rsi, [mn_movsxd]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 4
    call parse_modrm
    call read_disp
    ret
.c68:
    cmp al, 0x68                     ; push imm32
    jne .c6a
    lea rsi, [mn_push]
    mov [d_mnem], rsi
    mov byte [d_style], ST_IMM
    call set_imm_vsize
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.c6a:
    cmp al, 0x6a                     ; push imm8
    jne .c69
    lea rsi, [mn_push]
    mov [d_mnem], rsi
    mov byte [d_style], ST_IMM
    mov byte [d_imm_size], 1
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.c69:
    cmp al, 0x69                     ; imul r, r/m, imm32
    jne .c6b
    lea rsi, [mn_imul]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_IMM
    call parse_modrm
    call read_disp
    call set_imm_vsize
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.c6b:
    cmp al, 0x6b                     ; imul r, r/m, imm8
    jne .jcc8
    lea rsi, [mn_imul]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_IMM
    call parse_modrm
    call read_disp
    mov byte [d_imm_size], 1
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.jcc8:
    ; --- jcc rel8 (0x70..0x7F) ---
    cmp al, 0x70
    jb .grp1
    cmp al, 0x7f
    ja .grp1
    mov bl, al
    and bl, 0xf
    movzx ebx, bl
    lea rax, [jcc_tbl]
    mov rsi, [rax + rbx*8]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 1
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.grp1:
    ; --- group1 arithmetic with immediate (0x80..0x83) ---
    cmp al, 0x80
    jb .c84
    cmp al, 0x83
    ja .c84
    cmp al, 0x81
    je .g1v
    cmp al, 0x80
    je .g1b
    cmp al, 0x82
    je .g1b
    jmp .g1parse                    ; 0x83
.g1b:
    mov byte [d_byte], 1
.g1parse:
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_arith]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    cmp byte [d_op], 0x81
    je .g1immv
    mov byte [d_imm_size], 1
    cmp byte [d_op], 0x83
    jne .g1rd
    mov byte [d_imm_signed], 1
.g1rd:
    call read_imm
    ret
.g1v:
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_arith]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
.g1immv:
    call set_imm_vsize
    call read_imm
    ret
.c84:
    cmp al, 0x84                     ; test r/m8, r8
    jne .c85
    mov byte [d_byte], 1
    lea rsi, [mn_test]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c85:
    cmp al, 0x85                     ; test r/m, r
    jne .c86
    lea rsi, [mn_test]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c86:
    cmp al, 0x86                     ; xchg r/m8, r8
    jne .c87
    mov byte [d_byte], 1
    lea rsi, [mn_xchg]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c87:
    cmp al, 0x87                     ; xchg r/m, r
    jne .c88
    lea rsi, [mn_xchg]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c88:
    cmp al, 0x88                     ; mov r/m8, r8
    jne .c89
    mov byte [d_byte], 1
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c89:
    cmp al, 0x89                     ; mov r/m, r
    jne .c8a
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c8a:
    cmp al, 0x8a                     ; mov r8, r/m8
    jne .c8b
    mov byte [d_byte], 1
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.c8b:
    cmp al, 0x8b                     ; mov r, r/m
    jne .c8d
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.c8d:
    cmp al, 0x8d                     ; lea r, m
    jne .c8f
    lea rsi, [mn_lea]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM
    mov byte [d_nosize], 1
    call parse_modrm
    call read_disp
    ret
.c8f:
    cmp al, 0x8f                     ; pop r/m
    jne .c90
    lea rsi, [mn_pop]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM
    mov byte [d_defsize8], 1
    call parse_modrm
    call read_disp
    ret
.c90:
    cmp al, 0x90                     ; nop
    jne .c98
    lea rsi, [mn_nop]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.c98:
    cmp al, 0x98                     ; cwde / cdqe
    jne .c99
    test byte [d_rex], 8
    jz .c98w
    lea rsi, [mn_cdqe]
    jmp .c98s
.c98w:
    lea rsi, [mn_cwde]
.c98s:
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.c99:
    cmp al, 0x99                     ; cdq / cqo
    jne .ca8
    test byte [d_rex], 8
    jz .c99w
    lea rsi, [mn_cqo]
    jmp .c99s
.c99w:
    lea rsi, [mn_cdq]
.c99s:
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.ca8:
    cmp al, 0xa8                     ; test al, imm8
    jne .ca9
    mov byte [d_byte], 1
    lea rsi, [mn_test]
    mov [d_mnem], rsi
    mov byte [d_style], ST_ACC_IMM
    mov byte [d_imm_size], 1
    call read_imm
    ret
.ca9:
    cmp al, 0xa9                     ; test eAX, imm
    jne .cb0
    lea rsi, [mn_test]
    mov [d_mnem], rsi
    mov byte [d_style], ST_ACC_IMM
    call set_imm_vsize
    call read_imm
    ret
.cb0:
    cmp al, 0xb0                     ; mov r8, imm8
    jb .cb8
    cmp al, 0xb7
    ja .cb8
    mov bl, al
    and bl, 7
    test byte [d_rex], 1
    jz .b0r
    or bl, 8
.b0r:
    mov [d_reg], bl
    mov byte [d_byte], 1
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_IMM
    mov byte [d_imm_size], 1
    call read_imm
    ret
.cb8:
    cmp al, 0xb8                     ; mov r, imm (movabs if REX.W)
    jb .cc0
    cmp al, 0xbf
    ja .cc0
    mov bl, al
    and bl, 7
    test byte [d_rex], 1
    jz .b8r
    or bl, 8
.b8r:
    mov [d_reg], bl
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_IMM
    test byte [d_rex], 8
    jz .b8_32
    mov byte [d_imm_size], 8
    jmp .b8_rd
.b8_32:
    call set_imm_vsize
.b8_rd:
    call read_imm
    ret
.cc0:
    cmp al, 0xc0                     ; shift group r/m, imm8
    jne .cc1
    mov byte [d_byte], 1
.cc0common:
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_shift]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    mov byte [d_imm_size], 1
    call read_imm
    ret
.cc1:
    cmp al, 0xc1
    jne .cc2
    jmp .cc0common
.cc2:
    cmp al, 0xc2                     ; ret imm16
    jne .cc3
    lea rsi, [mn_ret]
    mov [d_mnem], rsi
    mov byte [d_style], ST_IMM
    mov byte [d_imm_size], 2
    call read_imm
    ret
.cc3:
    cmp al, 0xc3                     ; ret
    jne .cc6
    lea rsi, [mn_ret]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.cc6:
    cmp al, 0xc6                     ; mov r/m8, imm8
    jne .cc7
    mov byte [d_byte], 1
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    mov byte [d_imm_size], 1
    call read_imm
    ret
.cc7:
    cmp al, 0xc7                     ; mov r/m, imm
    jne .cc9
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    call set_imm_vsize
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.cc9:
    cmp al, 0xc9                     ; leave
    jne .ccc
    lea rsi, [mn_leave]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.ccc:
    cmp al, 0xcc                     ; int3
    jne .cd0
    lea rsi, [mn_int3]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.cd0:
    cmp al, 0xd0                     ; shift r/m, 1
    jne .cd1
    mov byte [d_byte], 1
.cd0common:
    mov byte [d_style], ST_RM_1
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_shift]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    ret
.cd1:
    cmp al, 0xd1
    jne .cd2
    jmp .cd0common
.cd2:
    cmp al, 0xd2                     ; shift r/m, cl
    jne .cd3
    mov byte [d_byte], 1
.cd2common:
    mov byte [d_style], ST_RM_CL
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_shift]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    ret
.cd3:
    cmp al, 0xd3
    jne .ce8
    jmp .cd2common
.ce8:
    cmp al, 0xe8                     ; call rel32
    jne .ce9
    lea rsi, [mn_call]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 4
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.ce9:
    cmp al, 0xe9                     ; jmp rel32
    jne .ceb
    lea rsi, [mn_jmp]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 4
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.ceb:
    cmp al, 0xeb                     ; jmp rel8
    jne .cf4
    lea rsi, [mn_jmp]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 1
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.cf4:
    cmp al, 0xf4                     ; hlt
    jne .cf6
    lea rsi, [mn_hlt]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.cf6:
    cmp al, 0xf6                     ; group3 byte
    jne .cf7
    mov byte [d_byte], 1
.cf6common:
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_f7]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    cmp ecx, 2                       ; reg 0/1 = test (has imm)
    jae .f6_rm
    mov byte [d_style], ST_RM_IMM
    cmp byte [d_op], 0xf6
    je .f6_imm8
    call set_imm_vsize
    call read_imm
    ret
.f6_imm8:
    mov byte [d_imm_size], 1
    call read_imm
    ret
.f6_rm:
    mov byte [d_style], ST_RM
    ret
.cf7:
    cmp al, 0xf7                     ; group3
    jne .cfe
    jmp .cf6common
.cfe:
    cmp al, 0xfe                     ; group4 inc/dec r/m8
    jne .cff
    mov byte [d_byte], 1
    call parse_modrm
    call read_disp
    mov byte [d_style], ST_RM
    movzx ecx, byte [d_reg]
    and ecx, 7
    cmp ecx, 0
    jne .fe_dec
    lea rsi, [mn_inc]
    jmp .fe_set
.fe_dec:
    lea rsi, [mn_dec]
.fe_set:
    mov [d_mnem], rsi
    ret
.cff:
    cmp al, 0xff                     ; group5
    jne .cstr
    call parse_modrm
    call read_disp
    mov byte [d_style], ST_RM
    movzx ecx, byte [d_reg]
    and ecx, 7
    cmp ecx, 0
    je .ff_inc
    cmp ecx, 1
    je .ff_dec
    cmp ecx, 2
    je .ff_call
    cmp ecx, 4
    je .ff_jmp
    cmp ecx, 6
    je .ff_push
    jmp .unknown
.ff_inc:
    lea rsi, [mn_inc]
    mov [d_mnem], rsi
    ret
.ff_dec:
    lea rsi, [mn_dec]
    mov [d_mnem], rsi
    ret
.ff_call:
    lea rsi, [mn_call]
    mov [d_mnem], rsi
    mov byte [d_defsize8], 1
    ret
.ff_jmp:
    lea rsi, [mn_jmp]
    mov [d_mnem], rsi
    mov byte [d_defsize8], 1
    ret
.ff_push:
    lea rsi, [mn_push]
    mov [d_mnem], rsi
    mov byte [d_defsize8], 1
    ret
.cstr:
    ; string operations: movs/cmps/stos/lods/scas (0xA4..0xA7, 0xAA..0xAF)
    cmp al, 0xa4
    jb .unknown
    cmp al, 0xa7
    jbe .cstr_do
    cmp al, 0xaa
    jb .unknown
    cmp al, 0xaf
    ja .unknown
.cstr_do:
    ; index into str_tbl = opcode - 0xa4
    movzx ecx, al
    sub ecx, 0xa4
    lea rax, [str_tbl]
    mov rsi, [rax + rcx*8]           ; base name pointer
    ; compose into strmnem: optional rep prefix, then base, then size suffix
    lea rdi, [strmnem]
    ; --- prefix ---
    cmp byte [d_rep], 1
    je .cstr_rep
    cmp byte [d_repne], 1
    je .cstr_repne
    jmp .cstr_base
.cstr_rep:
    ; cmps/scas use repz, others use rep
    cmp byte [d_op], 0xa6
    je .cstr_repz
    cmp byte [d_op], 0xa7
    je .cstr_repz
    cmp byte [d_op], 0xae
    je .cstr_repz
    cmp byte [d_op], 0xaf
    je .cstr_repz
    lea rbx, [pfx_rep]
    jmp .cstr_copy_pfx
.cstr_repz:
    lea rbx, [pfx_repz]
    jmp .cstr_copy_pfx
.cstr_repne:
    lea rbx, [pfx_repnz]
.cstr_copy_pfx:
    mov al, [rbx]
    test al, al
    jz .cstr_base
    mov [rdi], al
    inc rdi
    inc rbx
    jmp .cstr_copy_pfx
.cstr_base:
    mov al, [rsi]
    test al, al
    jz .cstr_suffix
    mov [rdi], al
    inc rdi
    inc rsi
    jmp .cstr_base
.cstr_suffix:
    ; even opcode -> byte 'b'; odd -> w/d/q by operand size
    test byte [d_op], 1
    jz .cstr_b
    test byte [d_rex], 8             ; REX.W -> q
    jnz .cstr_q
    cmp byte [d_opsize], 1           ; 0x66 -> w
    je .cstr_w
    mov al, 'd'
    jmp .cstr_put
.cstr_q:
    mov al, 'q'
    jmp .cstr_put
.cstr_w:
    mov al, 'w'
    jmp .cstr_put
.cstr_b:
    mov al, 'b'
.cstr_put:
    mov [rdi], al
    inc rdi
    mov byte [rdi], 0
    lea rsi, [strmnem]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.unknown:
    mov byte [d_style], 0xff
    ret

; decode_vex_payload - in dl = VEX byte containing vvvv/L/pp.
; Converts the inverted register field and records the vector length.
decode_vex_payload:
    mov byte [d_style], 0xff
    cmp byte [d_trunc], 1
    je .done
    mov al, dl
    shr al, 3
    and al, 0x0f
    xor al, 0x0f
    mov [d_vvvv], al
    mov al, dl
    and al, 4
    shr al, 2
    mov [d_vex_l], al
    and dl, 3
    mov [d_vex_pp], dl
    mov byte [d_style], ST_NONE
.done:
    ret

; decode_vex - decode the supported 128/256-bit VEX/AVX instruction subset.
decode_vex:
    cmp byte [d_vex_map], 1
    jne .unknown
    cmp byte [d_op], 0x10
    je .move_load
    cmp byte [d_op], 0x11
    je .move_store
    cmp byte [d_op], 0x28
    je .move_aligned_load
    cmp byte [d_op], 0x29
    je .move_aligned_store
    jmp .not_move
.move_load:
    mov byte [d_style], ST_REG_RM
    jmp .move
.move_store:
    mov byte [d_style], ST_RM_REG
    jmp .move
.move_aligned_load:
    mov byte [d_style], ST_REG_RM
    jmp .move
.move_aligned_store:
    mov byte [d_style], ST_RM_REG
.move:
    cmp byte [d_vex_pp], 1
    ja .unknown
    cmp byte [d_vvvv], 0        ; VEX.vvvv is reserved for these move forms
    jne .unknown
    cmp byte [d_op], 0x11
    jbe .unaligned_move
    cmp byte [d_vex_pp], 1
    je .aligned_pd
    lea rsi, [mn_vmovaps]
    jmp .move_ready
.aligned_pd:
    lea rsi, [mn_vmovapd]
    jmp .move_ready
.unaligned_move:
    cmp byte [d_vex_pp], 1
    je .unaligned_pd
    lea rsi, [mn_vmovups]
    jmp .move_ready
.unaligned_pd:
    lea rsi, [mn_vmovupd]
.move_ready:
    mov [d_mnem], rsi
    mov byte [d_vec], 1
    mov byte [d_vec_size], 16
    cmp byte [d_vex_l], 0
    je .move_operands
    mov byte [d_vec], 2
    mov byte [d_vec_size], 32
.move_operands:
    call parse_modrm
    call read_disp
    ret
.not_move:
    cmp byte [d_op], 0x77
    jne .packed
    cmp byte [d_vex_pp], 0
    jne .unknown
    cmp byte [d_vex_l], 0
    jne .unknown                 ; VEX.L=1 selects unsupported vzeroall
    cmp byte [d_vvvv], 0        ; reserved VEX.vvvv must be encoded as 1111
    jne .unknown
    lea rsi, [mn_vzeroupper]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.packed:
    cmp byte [d_op], 0x54
    jb .integer
    cmp byte [d_op], 0x5f
    ja .integer
    movzx ecx, byte [d_op]
    sub ecx, 0x54
    movzx eax, byte [d_vex_pp]
    cmp eax, 0
    je .ps
    cmp eax, 1
    je .pd
    cmp eax, 2
    je .ss
    lea rax, [vex_sd_tbl]
    jmp .lookup
.ps:
    lea rax, [vex_ps_tbl]
    jmp .lookup
.pd:
    lea rax, [vex_pd_tbl]
    jmp .lookup
.ss:
    lea rax, [vex_ss_tbl]
.lookup:
    mov rsi, [rax + rcx*8]
    test rsi, rsi
    jz .unknown
    cmp byte [d_vex_pp], 2
    jae .scalar
    mov [d_mnem], rsi
    mov byte [d_style], ST_VEC3
    mov byte [d_vec], 1
    mov byte [d_vec_size], 16
    cmp byte [d_vex_l], 0
    je .decode_operands
    mov byte [d_vec], 2
    mov byte [d_vec_size], 32
    jmp .decode_operands
.scalar:
    cmp byte [d_vex_l], 0
    jne .unknown                 ; scalar forms require VEX.L=0
    mov [d_mnem], rsi
    mov byte [d_style], ST_VEC3
    mov byte [d_vec], 1
    mov byte [d_vec_size], 4
    cmp byte [d_vex_pp], 3
    jne .decode_operands
    mov byte [d_vec_size], 8
.decode_operands:
    call parse_modrm
    call read_disp
    ret
.integer:
    cmp byte [d_vex_pp], 1
    jne .unknown                 ; packed integer forms require the 66 prefix
    cmp byte [d_op], 0xd4
    je .vpaddq
    cmp byte [d_op], 0xdb
    je .vpand
    cmp byte [d_op], 0xdf
    je .vpandn
    cmp byte [d_op], 0xeb
    je .vpor
    cmp byte [d_op], 0xef
    je .vpxor
    cmp byte [d_op], 0xf8
    je .vpsubb
    cmp byte [d_op], 0xf9
    je .vpsubw
    cmp byte [d_op], 0xfa
    je .vpsubd
    cmp byte [d_op], 0xfb
    je .vpsubq
    cmp byte [d_op], 0xfc
    je .vpaddb
    cmp byte [d_op], 0xfd
    je .vpaddw
    cmp byte [d_op], 0xfe
    je .vpaddd
    jmp .unknown
.vpand:
    lea rsi, [mn_vpand]
    jmp .integer_ready
.vpandn:
    lea rsi, [mn_vpandn]
    jmp .integer_ready
.vpor:
    lea rsi, [mn_vpor]
    jmp .integer_ready
.vpxor:
    lea rsi, [mn_vpxor]
    jmp .integer_ready
.vpaddb:
    lea rsi, [mn_vpaddb]
    jmp .integer_ready
.vpaddw:
    lea rsi, [mn_vpaddw]
    jmp .integer_ready
.vpaddd:
    lea rsi, [mn_vpaddd]
    jmp .integer_ready
.vpaddq:
    lea rsi, [mn_vpaddq]
    jmp .integer_ready
.vpsubb:
    lea rsi, [mn_vpsubb]
    jmp .integer_ready
.vpsubw:
    lea rsi, [mn_vpsubw]
    jmp .integer_ready
.vpsubd:
    lea rsi, [mn_vpsubd]
    jmp .integer_ready
.vpsubq:
    lea rsi, [mn_vpsubq]
.integer_ready:
    mov [d_mnem], rsi
    mov byte [d_style], ST_VEC3
    mov byte [d_vec], 1
    mov byte [d_vec_size], 16
    cmp byte [d_vex_l], 0
    je .integer_operands
    mov byte [d_vec], 2
    mov byte [d_vec_size], 32
.integer_operands:
    call parse_modrm
    call read_disp
    ret
.unknown:
    mov byte [d_style], 0xff
    ret

; decode_two_byte - in: al = second opcode byte (after 0x0F).
decode_two_byte:
    cmp al, 0x0b                     ; ud2
    jne .t10
    lea rsi, [mn_ud2]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.t10:
    cmp al, 0x10                     ; movups/movupd/movss/movsd xmm, xmm/mem
    jne .t11
    mov byte [d_style], ST_REG_RM
    call .set_sse_move
    cmp byte [d_style], 0xff
    je .tunknown
    call parse_modrm
    call read_disp
    ret
.t11:
    cmp al, 0x11                     ; movups/movupd/movss/movsd xmm/mem, xmm
    jne .t28
    mov byte [d_style], ST_RM_REG
    call .set_sse_move
    cmp byte [d_style], 0xff
    je .tunknown
    call parse_modrm
    call read_disp
    ret
.t28:
    cmp al, 0x28                     ; movaps/movapd xmm, xmm/mem
    jne .t29
    mov byte [d_style], ST_REG_RM
    call .set_sse_aligned_move
    cmp byte [d_style], 0xff
    je .tunknown
    call parse_modrm
    call read_disp
    ret
.t29:
    cmp al, 0x29                     ; movaps/movapd xmm/mem, xmm
    jne .tsse_packed_check
    mov byte [d_style], ST_RM_REG
    call .set_sse_aligned_move
    cmp byte [d_style], 0xff
    je .tunknown
    call parse_modrm
    call read_disp
    ret
.tsse_packed_check:
    cmp al, 0x54
    jb .t1e
    cmp al, 0x59
    jbe .tsse_packed
    cmp al, 0x5c
    jb .t1e
    cmp al, 0x5f
    ja .t1e
.tsse_packed:
    call .set_sse_packed
    cmp byte [d_style], 0xff
    je .tunknown
    call parse_modrm
    call read_disp
    ret
.t1e:
    cmp al, 0x05                     ; syscall
    jne .t1e_next
    lea rsi, [mn_syscall]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.t1e_next:
    cmp al, 0x1e                     ; endbr64 / endbr32 / nop r/m
    jne .t1f
    mov byte [d_style], ST_NONE
    call parse_modrm
    call read_disp
    cmp byte [d_rep], 1
    jne .t1e_nop
    cmp byte [d_modrm], 0xfa
    jne .t1e_fb
    lea rsi, [mn_endbr64]
    mov [d_mnem], rsi
    ret
.t1e_fb:
    lea rsi, [mn_nop]
    mov [d_mnem], rsi
    ret
.t1e_nop:
    lea rsi, [mn_nop]
    mov [d_mnem], rsi
    ret
.t1f:
    cmp al, 0x1f                     ; multi-byte nop r/m
    jne .t80
    lea rsi, [mn_nop]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM
    call parse_modrm
    call read_disp
    ret
.t80:
    cmp al, 0x80                     ; jcc rel32
    jb .t90
    cmp al, 0x8f
    ja .t90
    mov bl, al
    and bl, 0xf
    movzx ebx, bl
    lea rax, [jcc_tbl]
    mov rsi, [rax + rbx*8]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 4
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.t90:
    cmp al, 0x90                     ; setcc r/m8
    jb .ta2
    cmp al, 0x9f
    ja .ta2
    mov bl, al
    and bl, 0xf
    movzx ebx, bl
    lea rax, [set_tbl]
    mov rsi, [rax + rbx*8]
    mov [d_mnem], rsi
    mov byte [d_byte], 1
    mov byte [d_style], ST_RM
    call parse_modrm
    call read_disp
    ret
.ta2:
    cmp al, 0xa2                     ; cpuid
    jne .taf
    lea rsi, [mn_cpuid]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.taf:
    cmp al, 0xaf                     ; imul r, r/m
    jne .tb6
    lea rsi, [mn_imul]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.tb6:
    cmp al, 0xb6                     ; movzx r, r/m8
    jne .tb7
    lea rsi, [mn_movzx]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 1
    call parse_modrm
    call read_disp
    ret
.tb7:
    cmp al, 0xb7                     ; movzx r, r/m16
    jne .tbe
    lea rsi, [mn_movzx]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 2
    call parse_modrm
    call read_disp
    ret
.tbe:
    cmp al, 0xbe                     ; movsx r, r/m8
    jne .tbf
    lea rsi, [mn_movsx]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 1
    call parse_modrm
    call read_disp
    ret
.tbf:
    cmp al, 0xbf                     ; movsx r, r/m16
    jne .tunknown
    lea rsi, [mn_movsx]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 2
    call parse_modrm
    call read_disp
    ret
.tunknown:
    mov byte [d_style], 0xff
    ret

.set_sse_move:
    mov byte [d_vec], 1
    mov byte [d_vec_size], 16
    cmp byte [d_repne], 1
    je .ssm_sd
    cmp byte [d_rep], 1
    je .ssm_ss
    cmp byte [d_opsize], 1
    je .ssm_upd
    lea rsi, [mn_movups]
    mov [d_mnem], rsi
    ret
.ssm_upd:
    lea rsi, [mn_movupd]
    mov [d_mnem], rsi
    ret
.ssm_ss:
    cmp byte [d_opsize], 0
    jne .ssm_bad
    mov byte [d_vec_size], 4
    lea rsi, [mn_movss]
    mov [d_mnem], rsi
    ret
.ssm_sd:
    cmp byte [d_opsize], 0
    jne .ssm_bad
    mov byte [d_vec_size], 8
    lea rsi, [mn_movsd]
    mov [d_mnem], rsi
    ret
.ssm_bad:
    mov byte [d_style], 0xff
    ret

.set_sse_aligned_move:
    cmp byte [d_repne], 0
    jne .ssam_bad
    cmp byte [d_rep], 0
    jne .ssam_bad
    mov byte [d_vec], 1
    mov byte [d_vec_size], 16
    cmp byte [d_opsize], 1
    je .ssam_pd
    lea rsi, [mn_movaps]
    mov [d_mnem], rsi
    ret
.ssam_pd:
    lea rsi, [mn_movapd]
    mov [d_mnem], rsi
    ret
.ssam_bad:
    mov byte [d_style], 0xff
    ret

.set_sse_packed:
    cmp byte [d_repne], 0
    jne .ssp_bad
    cmp byte [d_rep], 0
    jne .ssp_bad
    mov byte [d_vec], 1
    mov byte [d_vec_size], 16
    movzx ecx, byte [d_op]
    sub ecx, 0x54
    lea rax, [sse_ps_tbl]
    cmp byte [d_opsize], 1
    jne .ssp_lookup
    lea rax, [sse_pd_tbl]
.ssp_lookup:
    mov rsi, [rax + rcx*8]
    test rsi, rsi
    jz .ssp_bad
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM
    ret
.ssp_bad:
    mov byte [d_style], 0xff
    ret

; ---------------------------------------------------------------------------
