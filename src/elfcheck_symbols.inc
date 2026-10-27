; GNU symbol versions. The version map is indexed by the 15-bit Versym index;
; names are copied out of .dynstr so later section reads cannot invalidate them.
; ---------------------------------------------------------------------------
prepare_symbol_versions:
    cmp byte [ver_ready], 0
    jne .psv_already
    push r13
    push r14
    push r15
    mov byte [ver_ready], 1
    mov byte [ver_versym_found], 0
    mov byte [ver_need_found], 0
    mov byte [ver_def_found], 0
    mov byte [ver_dynsym_found], 0
    mov qword [ver_strings_len], 0
    lea rdi, [ver_map_kind]
    xor eax, eax
    mov ecx, VER_MAP_COUNT
    cld
    rep stosb

    mov rdi, r12
    xor esi, esi
    mov edx, SEEK_END
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .psv_done
    mov [filesize], rax

    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .psv_done
    movzx r15d, word [ehdr + E_SHENTSIZE]
    cmp r15d, SHDR_SIZE
    jb .psv_done
    mov rax, r14
    mov rcx, r15
    mul rcx
    test rdx, rdx
    jnz .psv_done
    add rax, [ehdr + E_SHOFF]
    jc .psv_done
    cmp rax, [filesize]
    ja .psv_done

    xor r13, r13
.psv_scan:
    cmp r13, r14
    jae .psv_parse
    mov rax, r13
    imul rax, r15
    add rax, [ehdr + E_SHOFF]
    jc .psv_parse
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .psv_parse
    mov rdi, r12
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    xor eax, eax
    syscall
    cmp rax, SHDR_SIZE
    jne .psv_parse

    mov eax, dword [shdr + SH_TYPE]
    cmp eax, 11                 ; SHT_DYNSYM
    jne .psv_check_versym
    cmp byte [ver_dynsym_found], 0
    jne .psv_check_versym
    mov byte [ver_dynsym_found], 1
    mov eax, dword [shdr + SH_LINK]
    mov [ver_dynsym_link], eax
.psv_check_versym:
    cmp eax, 0x6fffffff         ; SHT_GNU_versym
    jne .psv_check_need
    cmp byte [ver_versym_found], 0
    jne .psv_check_need
    mov byte [ver_versym_found], 1
    mov rax, [shdr + SH_OFFSET]
    mov [ver_versym_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [ver_versym_size], rax
    mov eax, dword [shdr + SH_LINK]
    mov [ver_versym_link], eax
    jmp .psv_next
.psv_check_need:
    cmp eax, 0x6ffffffe         ; SHT_GNU_verneed
    jne .psv_check_def
    cmp byte [ver_need_found], 0
    jne .psv_check_def
    mov byte [ver_need_found], 1
    mov rax, [shdr + SH_OFFSET]
    mov [ver_need_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [ver_need_size], rax
    mov eax, dword [shdr + SH_LINK]
    mov [ver_need_link], eax
    jmp .psv_next
.psv_check_def:
    cmp eax, 0x6ffffffd         ; SHT_GNU_verdef
    jne .psv_next
    cmp byte [ver_def_found], 0
    jne .psv_next
    mov byte [ver_def_found], 1
    mov rax, [shdr + SH_OFFSET]
    mov [ver_def_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [ver_def_size], rax
    mov eax, dword [shdr + SH_LINK]
    mov [ver_def_link], eax
.psv_next:
    inc r13
    jmp .psv_scan
.psv_parse:
    cmp byte [ver_need_found], 0
    je .psv_def
    call parse_version_needs
.psv_def:
    cmp byte [ver_def_found], 0
    je .psv_restore
    call parse_version_definitions
.psv_restore:
    cmp byte [ver_dynsym_found], 0
    je .psv_done
    mov eax, [ver_dynsym_link]
    call load_dynstr
.psv_done:
    pop r15
    pop r14
    pop r13
.psv_already:
    ret

; Bounds-check [ver_rel, ver_rel + ver_bytes) in the current version section.
version_range_ok:
    mov rax, [ver_rel]
    add rax, [ver_bytes]
    jc .vro_no
    cmp rax, [ver_parse_size]
    ja .vro_no
    mov rdx, [ver_parse_off]
    add rdx, [ver_rel]
    jc .vro_no
    add rdx, [ver_bytes]
    jc .vro_no
    cmp rdx, [filesize]
    ja .vro_no
    mov eax, 1
    ret
.vro_no:
    xor eax, eax
    ret

; Read rdx bytes at rax into rsi. Returns eax=1 only for a complete read.
read_version_at:
    mov [ver_read_off], rax
    mov [ver_read_buf], rsi
    mov [ver_read_size], rdx
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .rva_no
    mov rdi, r12
    mov rsi, [ver_read_buf]
    mov rdx, [ver_read_size]
    xor eax, eax
    syscall
    cmp rax, [ver_read_size]
    jne .rva_no
    mov eax, 1
    ret
.rva_no:
    xor eax, eax
    ret

; Copy an offset in dynstr into the stable version-string buffer. In: eax offset.
; Out: rax copied offset, or -1 if either buffer cannot hold the string.
copy_version_string:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    mov ebx, eax
    cmp rbx, [dynstr_len]
    jae .cvs_bad
    mov rdx, [ver_strings_len]
    cmp rdx, VERSTR_CAP
    jae .cvs_bad
    mov [ver_copy_start], rdx
    lea rsi, [rel dynstr]
    add rsi, rbx
    lea rdi, [rel ver_strings]
    add rdi, rdx
.cvs_loop:
    cmp rdx, VERSTR_CAP
    jae .cvs_bad
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    inc rdx
    test al, al
    jz .cvs_done
    jmp .cvs_loop
.cvs_done:
    mov [ver_strings_len], rdx
    mov rax, [ver_copy_start]
    jmp .cvs_out
.cvs_bad:
    mov rax, -1
.cvs_out:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

parse_version_needs:
    push rbx
    push r13
    push r14
    mov eax, [ver_need_link]
    test eax, eax
    jz .pvn_done
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .pvn_done
    call load_dynstr
    cmp dword [shdr + SH_TYPE], 3 ; SHT_STRTAB
    jne .pvn_done
    mov rax, [ver_need_off]
    mov [ver_parse_off], rax
    mov rax, [ver_need_size]
    mov [ver_parse_size], rax
    mov qword [ver_record_rel], 0
.pvn_record:
    mov rax, [ver_record_rel]
    mov [ver_rel], rax
    mov qword [ver_bytes], 16
    call version_range_ok
    test eax, eax
    jz .pvn_done
    mov rax, [ver_parse_off]
    add rax, [ver_record_rel]
    jc .pvn_done
    lea rsi, [ver_need_record]
    mov edx, 16
    call read_version_at
    test eax, eax
    jz .pvn_done

    movzx eax, word [ver_need_record + 2]
    mov [ver_aux_count], eax
    mov eax, dword [ver_need_record + 4]
    mov [ver_library_src], eax
    mov eax, dword [ver_need_record + 8]
    test eax, eax
    jz .pvn_next_record
    add rax, [ver_record_rel]
    jc .pvn_next_record
    mov [ver_aux_rel], rax
    mov dword [ver_aux_index], 0
.pvn_aux:
    mov eax, [ver_aux_index]
    cmp eax, [ver_aux_count]
    jae .pvn_next_record
    mov rax, [ver_aux_rel]
    mov [ver_rel], rax
    mov qword [ver_bytes], 16
    call version_range_ok
    test eax, eax
    jz .pvn_next_record
    mov rax, [ver_parse_off]
    add rax, [ver_aux_rel]
    jc .pvn_next_record
    lea rsi, [ver_need_aux]
    mov edx, 16
    call read_version_at
    test eax, eax
    jz .pvn_next_record

    movzx eax, word [ver_need_aux + 6]
    and eax, 0x7fff
    cmp eax, 2
    jb .pvn_aux_next
    mov [ver_cur_index], eax
    mov eax, dword [ver_need_aux + 8]
    call copy_version_string
    cmp rax, -1
    je .pvn_aux_next
    mov [ver_copied_name], eax
    mov eax, [ver_library_src]
    call copy_version_string
    cmp rax, -1
    je .pvn_aux_next
    mov [ver_copied_library], eax
    mov eax, [ver_cur_index]
    lea rdi, [rel ver_map_kind]
    mov byte [rdi + rax], 1
    mov edx, [ver_cur_index]
    shl rdx, 2
    mov eax, [ver_copied_name]
    lea rdi, [rel ver_map_name]
    mov [rdi + rdx], eax
    mov eax, [ver_copied_library]
    lea rdi, [rel ver_map_library]
    mov [rdi + rdx], eax
.pvn_aux_next:
    inc dword [ver_aux_index]
    mov eax, dword [ver_need_aux + 12]
    test eax, eax
    jz .pvn_next_record
    add [ver_aux_rel], rax
    jc .pvn_next_record
    jmp .pvn_aux
.pvn_next_record:
    mov eax, dword [ver_need_record + 12]
    test eax, eax
    jz .pvn_done
    add [ver_record_rel], rax
    jc .pvn_done
    jmp .pvn_record
.pvn_done:
    pop r14
    pop r13
    pop rbx
    ret

parse_version_definitions:
    push rbx
    push r13
    push r14
    mov eax, [ver_def_link]
    test eax, eax
    jz .pvd_done
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .pvd_done
    call load_dynstr
    cmp dword [shdr + SH_TYPE], 3 ; SHT_STRTAB
    jne .pvd_done
    mov rax, [ver_def_off]
    mov [ver_parse_off], rax
    mov rax, [ver_def_size]
    mov [ver_parse_size], rax
    mov qword [ver_record_rel], 0
.pvd_record:
    mov rax, [ver_record_rel]
    mov [ver_rel], rax
    mov qword [ver_bytes], 20
    call version_range_ok
    test eax, eax
    jz .pvd_done
    mov rax, [ver_parse_off]
    add rax, [ver_record_rel]
    jc .pvd_done
    lea rsi, [ver_def_record]
    mov edx, 20
    call read_version_at
    test eax, eax
    jz .pvd_done

    movzx eax, word [ver_def_record + 6]
    test eax, eax
    jz .pvd_next_record
    movzx eax, word [ver_def_record + 4]
    and eax, 0x7fff
    cmp eax, 2
    jb .pvd_next_record
    mov [ver_cur_index], eax
    mov eax, dword [ver_def_record + 12]
    test eax, eax
    jz .pvd_next_record
    add rax, [ver_record_rel]
    jc .pvd_next_record
    mov [ver_aux_rel], rax
    mov rax, [ver_aux_rel]
    mov [ver_rel], rax
    mov qword [ver_bytes], 8
    call version_range_ok
    test eax, eax
    jz .pvd_next_record
    mov rax, [ver_parse_off]
    add rax, [ver_aux_rel]
    jc .pvd_next_record
    lea rsi, [ver_def_aux]
    mov edx, 8
    call read_version_at
    test eax, eax
    jz .pvd_next_record
    mov eax, dword [ver_def_aux]
    call copy_version_string
    cmp rax, -1
    je .pvd_next_record
    mov [ver_copied_name], eax
    mov eax, [ver_cur_index]
    lea rdi, [rel ver_map_kind]
    mov byte [rdi + rax], 2
    mov edx, [ver_cur_index]
    shl rdx, 2
    mov eax, [ver_copied_name]
    lea rdi, [rel ver_map_name]
    mov [rdi + rdx], eax
    lea rdi, [rel ver_map_library]
    mov dword [rdi + rdx], 0
.pvd_next_record:
    mov eax, dword [ver_def_record + 16]
    test eax, eax
    jz .pvd_done
    add [ver_record_rel], rax
    jc .pvd_done
    jmp .pvd_record
.pvd_done:
    pop r14
    pop r13
    pop rbx
    ret

; In: rdi = symbol-table section index, rsi = symbol index.
; Returns version data in the ver_lookup_* fields; kind 1=required, 2=defined.
lookup_symbol_version:
    mov [ver_lookup_table], rdi
    mov [ver_lookup_symbol], rsi
    mov dword [ver_lookup_index], 0
    mov byte [ver_lookup_kind], 0
    mov byte [ver_lookup_hidden], 0
    mov dword [ver_lookup_name_off], 0
    mov dword [ver_lookup_library_off], 0
    call prepare_symbol_versions
    cmp byte [ver_versym_found], 0
    je .lsv_done
    mov eax, [ver_versym_link]
    cmp rax, [ver_lookup_table]
    jne .lsv_done
    mov rax, [ver_lookup_symbol]
    shl rax, 1
    jc .lsv_done
    mov rcx, rax
    add rcx, 2
    jc .lsv_done
    cmp rcx, [ver_versym_size]
    ja .lsv_done
    mov rdx, [ver_versym_off]
    add rdx, rax
    jc .lsv_done
    mov rcx, rdx
    add rcx, 2
    jc .lsv_done
    cmp rcx, [filesize]
    ja .lsv_done
    lea rsi, [ver_versym_entry]
    mov edx, 2
    mov rax, [ver_lookup_symbol]
    shl rax, 1
    jc .lsv_done
    add rax, [ver_versym_off]
    jc .lsv_done
    call read_version_at
    test eax, eax
    jz .lsv_done
    movzx eax, word [ver_versym_entry]
    test eax, 0x8000
    jz .lsv_visible
    mov byte [ver_lookup_hidden], 1
.lsv_visible:
    and eax, 0x7fff
    cmp eax, 2
    jb .lsv_done
    mov [ver_lookup_index], eax
    lea rdx, [rel ver_map_kind]
    movzx ecx, byte [rdx + rax]
    test ecx, ecx
    jz .lsv_done
    mov [ver_lookup_kind], cl
    mov edx, [ver_lookup_index]
    shl rdx, 2
    lea rdi, [rel ver_map_name]
    mov eax, [rdi + rdx]
    mov [ver_lookup_name_off], eax
    lea rdi, [rel ver_map_library]
    mov eax, [rdi + rdx]
    mov [ver_lookup_library_off], eax
.lsv_done:
    ret

print_symbol_version_suffix:
    call lookup_symbol_version
    cmp byte [ver_lookup_kind], 0
    je .psvs_done
    cmp byte [ver_lookup_kind], 2
    jne .psvs_single
    cmp byte [ver_lookup_hidden], 0
    jne .psvs_single
    PRINT sym_version_atat
    jmp .psvs_name
.psvs_single:
    PRINT sym_version_at
.psvs_name:
    lea rsi, [ver_strings]
    mov eax, [ver_lookup_name_off]
    add rsi, rax
    call print_cstr
.psvs_done:
    ret

emit_symbol_json_version:
    PRINT jk_version
    cmp dword [sym_table_type], 11 ; only SHT_DYNSYM has Versym entries
    jne .esjv_none
    mov rdi, [sym_table_index]
    mov rsi, [sym_entry_index]
    call lookup_symbol_version
    cmp byte [ver_lookup_kind], 0
    jne .esjv_object
.esjv_none:
    PRINT j_null
    ret
.esjv_object:
    PRINT j_lbrace
    PRINT jk_index
    mov eax, [ver_lookup_index]
    call print_dec
    PRINT j_comma
    PRINT jk_name
    lea rsi, [ver_strings]
    mov eax, [ver_lookup_name_off]
    add rsi, rax
    call jstr
    PRINT j_comma
    PRINT jk_kind
    cmp byte [ver_lookup_kind], 1
    jne .esjv_defined
    lea rsi, [sym_version_required]
    jmp .esjv_kind
.esjv_defined:
    lea rsi, [sym_version_defined]
.esjv_kind:
    call jname
    PRINT j_comma
    PRINT jk_library
    cmp byte [ver_lookup_kind], 1
    jne .esjv_no_library
    lea rsi, [ver_strings]
    mov eax, [ver_lookup_library_off]
    add rsi, rax
    call jstr
    jmp .esjv_hidden
.esjv_no_library:
    PRINT j_null
.esjv_hidden:
    PRINT j_comma
    PRINT jk_hidden
    cmp byte [ver_lookup_hidden], 0
    je .esjv_visible
    PRINT j_true
    jmp .esjv_end
.esjv_visible:
    PRINT j_false
.esjv_end:
    PRINT j_rbrace
    ret

; Symbol tables. These are opt-in in the text report because they can be large;
; JSON remains complete and always includes them.
; ---------------------------------------------------------------------------
print_symbol_tables:
    PRINT sym_title
    mov byte [sym_json_mode], 0
    call walk_symbol_tables
    cmp qword [sym_tables_found], 0
    jne .pst_done
    PRINT sym_none
.pst_done:
    ret

json_symbol_tables:
    PRINT jk_symbol_tables
    PRINT j_lbrack
    mov byte [sym_json_mode], 1
    mov byte [sym_table_first], 1
    call walk_symbol_tables
    mov byte [sym_json_mode], 0
    PRINT j_rbrack
    ret

; walk_symbol_tables scans SHT_SYMTAB and SHT_DYNSYM sections. All section and
; symbol reads are range-checked before access. r12 is the input file descriptor.
walk_symbol_tables:
    mov qword [sym_tables_found], 0
    mov rdi, r12
    xor esi, esi
    mov edx, SEEK_END
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .wst_done
    mov [filesize], rax

    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .wst_done
    movzx ecx, word [ehdr + E_SHENTSIZE]
    cmp ecx, SHDR_SIZE
    jb .wst_done
    mov rax, r14
    mul rcx
    test rdx, rdx
    jnz .wst_done
    add rax, [ehdr + E_SHOFF]
    jc .wst_done
    cmp rax, [filesize]
    ja .wst_done

    call load_shstrtab
    xor r13, r13
.wst_scan:
    cmp r13, r14
    jae .wst_done
    movzx eax, word [ehdr + E_SHENTSIZE]
    imul rax, r13
    add rax, [ehdr + E_SHOFF]
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    mov eax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jl .wst_done

    mov eax, dword [shdr + SH_TYPE]
    cmp eax, 2                    ; SHT_SYMTAB
    je .wst_symtab
    cmp eax, 11                   ; SHT_DYNSYM
    jne .wst_next
    mov dword [sym_table_type], 11
    jmp .wst_match
.wst_symtab:
    mov dword [sym_table_type], 2
.wst_match:
    mov [sym_table_index], r13
    mov rax, [shdr + SH_OFFSET]
    mov [sym_table_offset], rax
    mov rax, [shdr + SH_SIZE]
    mov [sym_table_size], rax
    mov rax, [shdr + SH_ENTSIZE]
    mov [sym_table_entsize], rax
    mov eax, dword [shdr + SH_LINK]
    mov [sym_table_link], eax
    call section_name_ptr
    mov [sym_table_name], rsi

    mov byte [sym_table_valid], 1
    mov qword [sym_entry_count], 0
    mov rax, [sym_table_entsize]
    cmp rax, 24                  ; Elf64_Sym is 24 bytes
    jb .wst_bad_table
    mov rax, [sym_table_offset]
    add rax, [sym_table_size]
    jc .wst_bad_table
    cmp rax, [filesize]
    ja .wst_bad_table
    mov rax, [sym_table_size]
    xor edx, edx
    div qword [sym_table_entsize]
    test rdx, rdx
    jnz .wst_bad_table
    mov [sym_entry_count], rax
    jmp .wst_table_valid
.wst_bad_table:
    mov byte [sym_table_valid], 0
.wst_table_valid:
    mov qword [dynstr_len], 0
    mov byte [sym_str_valid], 0
    mov eax, dword [sym_table_link]
    test eax, eax
    jz .wst_string_ready
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .wst_string_ready
    call load_dynstr
    cmp dword [shdr + SH_TYPE], 3 ; SHT_STRTAB
    jne .wst_string_bad
    mov byte [sym_str_valid], 1
    jmp .wst_string_ready
.wst_string_bad:
    mov qword [dynstr_len], 0
.wst_string_ready:
    inc qword [sym_tables_found]
    cmp byte [sym_json_mode], 0
    jne .wst_json_table
    call emit_symbol_table_text_header
    jmp .wst_emit_table
.wst_json_table:
    call emit_symbol_table_json_header
.wst_emit_table:
    mov qword [sym_entry_index], 0
    mov byte [sym_item_first], 1
.wst_symbol_loop:
    mov rax, [sym_entry_index]
    cmp rax, [sym_entry_count]
    jae .wst_symbol_done
    mul qword [sym_table_entsize]
    test rdx, rdx
    jnz .wst_symbol_done
    add rax, [sym_table_offset]
    jc .wst_symbol_done
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [syment]
    mov edx, 24
    mov eax, SYS_READ
    syscall
    cmp rax, 24
    jl .wst_symbol_done
    cmp byte [sym_json_mode], 0
    jne .wst_emit_json_symbol
    call emit_symbol_text
    jmp .wst_next_symbol
.wst_emit_json_symbol:
    call emit_symbol_json
.wst_next_symbol:
    inc qword [sym_entry_index]
    jmp .wst_symbol_loop
.wst_symbol_done:
    cmp byte [sym_json_mode], 0
    je .wst_next
    PRINT j_rbrack
    PRINT j_rbrace
.wst_next:
    inc r13
    jmp .wst_scan
.wst_done:
    ret

emit_symbol_table_text_header:
    PRINT sym_table_pre
    mov rsi, [sym_table_name]
    call print_cstr
    PRINT sym_table_mid
    mov rax, [sym_table_index]
    call print_dec
    PRINT sym_table_cnt
    mov rax, [sym_entry_count]
    call print_dec
    PRINT sym_table_end
    PRINT sym_colhdr
    cmp byte [sym_table_valid], 0
    jne .esth_strtab
    PRINT sym_bad_meta
.esth_strtab:
    cmp byte [sym_str_valid], 0
    jne .esth_done
    PRINT sym_bad_strtab
.esth_done:
    ret

emit_symbol_table_json_header:
    cmp byte [sym_table_first], 1
    je .estj_first
    PRINT j_comma
.estj_first:
    mov byte [sym_table_first], 0
    PRINT j_lbrace
    PRINT jk_index
    mov rax, [sym_table_index]
    call print_dec
    PRINT j_comma
    PRINT jk_name
    mov rsi, [sym_table_name]
    call jstr
    PRINT j_comma
    PRINT jk_kind
    cmp dword [sym_table_type], 2
    jne .estj_dynsym
    lea rsi, [sym_type_symtab]
    jmp .estj_kind
.estj_dynsym:
    lea rsi, [sym_type_dynsym]
.estj_kind:
    call jname
    PRINT j_comma
    PRINT jk_entry_count
    mov rax, [sym_entry_count]
    call print_dec
    PRINT j_comma
    PRINT jk_valid
    cmp byte [sym_table_valid], 0
    je .estj_invalid
    PRINT j_true
    jmp .estj_strings
.estj_invalid:
    PRINT j_false
.estj_strings:
    PRINT j_comma
    PRINT jk_strings_valid
    cmp byte [sym_str_valid], 0
    je .estj_no_strings
    PRINT j_true
    jmp .estj_symbols
.estj_no_strings:
    PRINT j_false
.estj_symbols:
    PRINT j_comma
    PRINT jk_symbols
    PRINT j_lbrack
    ret

emit_symbol_text:
    PRINT two_spaces
    mov rax, [sym_entry_index]
    mov ecx, 6
    call pfield_dec
    mov rax, [syment + 8]
    mov ecx, 19
    call pfield_hex
    mov rax, [syment + 16]
    mov ecx, 10
    call pfield_dec
    movzx eax, byte [syment + 4]
    and eax, 0x0f
    call symbol_type_name
    mov rsi, rax
    mov ecx, 11
    call print_cstr_pad
    movzx eax, byte [syment + 4]
    shr eax, 4
    call symbol_binding_name
    mov rsi, rax
    mov ecx, 11
    call print_cstr_pad
    movzx eax, byte [syment + 5]
    and eax, 3
    call symbol_visibility_name
    mov rsi, rax
    mov ecx, 11
    call print_cstr_pad
    movzx eax, word [syment + 6]
    cmp eax, 0
    je .est_und
    cmp eax, 0xfff1
    je .est_abs
    cmp eax, 0xfff2
    je .est_com
    cmp eax, 0xffff
    je .est_xindex
    mov ecx, 9
    call pfield_dec
    jmp .est_name
.est_und:
    lea rsi, [sym_und]
    jmp .est_special
.est_abs:
    lea rsi, [sym_abs]
    jmp .est_special
.est_com:
    lea rsi, [sym_com]
    jmp .est_special
.est_xindex:
    lea rsi, [sym_xindex]
.est_special:
    mov ecx, 9
    call print_cstr_pad
.est_name:
    mov eax, dword [syment]
    call dynstr_name_ptr
    call print_cstr
    cmp dword [sym_table_type], 11
    jne .est_no_version
    mov rdi, [sym_table_index]
    mov rsi, [sym_entry_index]
    call print_symbol_version_suffix
.est_no_version:
    PRINT nl
    ret

emit_symbol_json:
    cmp byte [sym_item_first], 1
    je .esj_first
    PRINT j_comma
.esj_first:
    mov byte [sym_item_first], 0
    PRINT j_lbrace
    PRINT jk_name
    mov eax, dword [syment]
    call dynstr_name_ptr
    call jstr
    PRINT j_comma
    PRINT jk_value
    mov rax, [syment + 8]
    call jhex
    PRINT j_comma
    PRINT jk_size
    mov rax, [syment + 16]
    call print_dec
    PRINT j_comma
    PRINT jk_type
    movzx eax, byte [syment + 4]
    and eax, 0x0f
    call symbol_type_name
    mov rsi, rax
    call jname
    PRINT j_comma
    PRINT jk_binding
    movzx eax, byte [syment + 4]
    shr eax, 4
    call symbol_binding_name
    mov rsi, rax
    call jname
    PRINT j_comma
    PRINT jk_visibility
    movzx eax, byte [syment + 5]
    and eax, 3
    call symbol_visibility_name
    mov rsi, rax
    call jname
    PRINT j_comma
    PRINT jk_section_index
    movzx eax, word [syment + 6]
    call print_dec
    PRINT j_comma
    PRINT jk_section_kind
    call emit_symbol_json_section_kind
    PRINT j_comma
    call emit_symbol_json_version
    PRINT j_rbrace
    ret

emit_symbol_json_section_kind:
    movzx eax, word [syment + 6]
    cmp eax, 0
    je .esjk_und
    cmp eax, 0xfff1
    je .esjk_abs
    cmp eax, 0xfff2
    je .esjk_com
    cmp eax, 0xffff
    je .esjk_xindex
    PRINT j_null
    ret
.esjk_und:
    lea rsi, [sym_und]
    jmp .esjk_string
.esjk_abs:
    lea rsi, [sym_abs]
    jmp .esjk_string
.esjk_com:
    lea rsi, [sym_com]
    jmp .esjk_string
.esjk_xindex:
    lea rsi, [sym_xindex]
.esjk_string:
    call jname
    ret

symbol_type_name:
    cmp eax, 0
    je .stn_notype
    cmp eax, 1
    je .stn_object
    cmp eax, 2
    je .stn_func
    cmp eax, 3
    je .stn_section
    cmp eax, 4
    je .stn_file
    cmp eax, 5
    je .stn_common
    cmp eax, 6
    je .stn_tls
    cmp eax, 10
    je .stn_ifunc
    lea rax, [sym_unknown]
    ret
.stn_notype:
    lea rax, [sym_notype]
    ret
.stn_object:
    lea rax, [sym_object]
    ret
.stn_func:
    lea rax, [sym_func]
    ret
.stn_section:
    lea rax, [sym_section]
    ret
.stn_file:
    lea rax, [sym_file]
    ret
.stn_common:
    lea rax, [sym_common]
    ret
.stn_tls:
    lea rax, [sym_tls]
    ret
.stn_ifunc:
    lea rax, [sym_ifunc]
    ret

symbol_binding_name:
    cmp eax, 0
    je .sbn_local
    cmp eax, 1
    je .sbn_global
    cmp eax, 2
    je .sbn_weak
    cmp eax, 10
    je .sbn_unique
    lea rax, [sym_unknown]
    ret
.sbn_local:
    lea rax, [sym_local]
    ret
.sbn_global:
    lea rax, [sym_global]
    ret
.sbn_weak:
    lea rax, [sym_weak]
    ret
.sbn_unique:
    lea rax, [sym_unique]
    ret

symbol_visibility_name:
    cmp eax, 0
    je .svn_default
    cmp eax, 1
    je .svn_internal
    cmp eax, 2
    je .svn_hidden
    cmp eax, 3
    je .svn_protected
    lea rax, [sym_unknown]
    ret
.svn_default:
    lea rax, [sym_default]
    ret
.svn_internal:
    lea rax, [sym_internal]
    ret
.svn_hidden:
    lea rax, [sym_hidden]
    ret
.svn_protected:
    lea rax, [sym_protected]
    ret

; ---------------------------------------------------------------------------
; Relocation sections. REL/RELA tables are opt-in in text mode because they can
; be verbose. Symbol names are resolved through sh_link -> symtab -> strtab.
; ---------------------------------------------------------------------------
print_relocation_tables:
    PRINT rel_title
    mov byte [rel_json_mode], 0
    call walk_relocation_tables
    cmp qword [rel_tables_found], 0
    jne .prt_done
    PRINT rel_none
.prt_done:
    ret

json_relocation_tables:
    PRINT jk_relocation_tables
    PRINT j_lbrack
    mov byte [rel_json_mode], 1
    mov byte [rel_table_first], 1
    call walk_relocation_tables
    mov byte [rel_json_mode], 0
    PRINT j_rbrack
    ret

walk_relocation_tables:
    mov qword [rel_tables_found], 0
    mov rdi, r12
    xor esi, esi
    mov edx, SEEK_END
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .wrt_done
    mov [filesize], rax

    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .wrt_done
    movzx ecx, word [ehdr + E_SHENTSIZE]
    cmp ecx, SHDR_SIZE
    jb .wrt_done
    mov rax, r14
    mul rcx
    test rdx, rdx
    jnz .wrt_done
    add rax, [ehdr + E_SHOFF]
    jc .wrt_done
    cmp rax, [filesize]
    ja .wrt_done

    call load_shstrtab
    xor r13, r13
.wrt_scan:
    cmp r13, r14
    jae .wrt_done
    movzx eax, word [ehdr + E_SHENTSIZE]
    imul rax, r13
    add rax, [ehdr + E_SHOFF]
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    mov eax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jl .wrt_done

    mov eax, dword [shdr + SH_TYPE]
    cmp eax, 4                    ; SHT_RELA
    je .wrt_rela
    cmp eax, 9                    ; SHT_REL
    jne .wrt_next
    mov dword [rel_table_type], 9
    jmp .wrt_match
.wrt_rela:
    mov dword [rel_table_type], 4
.wrt_match:
    mov [rel_table_index], r13
    mov rax, [shdr + SH_OFFSET]
    mov [rel_table_offset], rax
    mov rax, [shdr + SH_SIZE]
    mov [rel_table_size], rax
    mov rax, [shdr + SH_ENTSIZE]
    mov [rel_table_entsize], rax
    mov eax, dword [shdr + SH_LINK]
    mov [rel_table_link], eax
    mov eax, dword [shdr + SH_INFO]
    mov [rel_target_index], eax
    call section_name_ptr
    mov [rel_table_name], rsi

    mov byte [rel_target_valid], 0
    lea rax, [empty_str]
    mov [rel_target_name], rax
    mov eax, dword [rel_target_index]
    test eax, eax
    jz .wrt_target_done
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .wrt_target_done
    movzx ecx, word [ehdr + E_SHENTSIZE]
    imul rax, rcx
    add rax, [ehdr + E_SHOFF]
    jc .wrt_target_done
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    mov eax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jl .wrt_target_done
    call section_name_ptr
    mov [rel_target_name], rsi
    mov byte [rel_target_valid], 1
.wrt_target_done:

    mov byte [rel_table_valid], 1
    mov qword [rel_entry_count], 0
    mov rax, [rel_table_entsize]
    cmp dword [rel_table_type], 4
    jne .wrt_min_rel
    cmp rax, 24                  ; Elf64_Rela
    jb .wrt_bad_table
    jmp .wrt_check_range
.wrt_min_rel:
    cmp rax, 16                  ; Elf64_Rel
    jb .wrt_bad_table
.wrt_check_range:
    mov rax, [rel_table_offset]
    add rax, [rel_table_size]
    jc .wrt_bad_table
    cmp rax, [filesize]
    ja .wrt_bad_table
    mov rax, [rel_table_size]
    xor edx, edx
    div qword [rel_table_entsize]
    test rdx, rdx
    jnz .wrt_bad_table
    mov [rel_entry_count], rax
    jmp .wrt_metadata_done
.wrt_bad_table:
    mov byte [rel_table_valid], 0
.wrt_metadata_done:
    call load_relocation_symbols
    inc qword [rel_tables_found]
    cmp byte [rel_json_mode], 0
    jne .wrt_json_header
    call emit_relocation_text_header
    jmp .wrt_entries
.wrt_json_header:
    call emit_relocation_json_header
.wrt_entries:
    mov qword [rel_entry_index], 0
    mov byte [rel_item_first], 1
.wrt_entry_loop:
    mov rax, [rel_entry_index]
    cmp rax, [rel_entry_count]
    jae .wrt_entries_done
    mul qword [rel_table_entsize]
    test rdx, rdx
    jnz .wrt_entries_done
    add rax, [rel_table_offset]
    jc .wrt_entries_done
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    mov qword [rel_entry + 16], 0
    mov rdi, r12
    lea rsi, [rel_entry]
    mov edx, 16
    cmp dword [rel_table_type], 4
    jne .wrt_read_entry
    mov edx, 24
.wrt_read_entry:
    mov eax, SYS_READ
    syscall
    cmp dword [rel_table_type], 4
    jne .wrt_check_rel_read
    cmp rax, 24
    jl .wrt_entries_done
    jmp .wrt_parse_entry
.wrt_check_rel_read:
    cmp rax, 16
    jl .wrt_entries_done
.wrt_parse_entry:
    mov rax, [rel_entry]
    mov [rel_offset], rax
    mov rax, [rel_entry + 8]
    mov [rel_info], rax
    mov edx, eax
    mov [rel_type_id], edx
    shr rax, 32
    mov [rel_symbol_index], eax
    cmp dword [rel_table_type], 4
    jne .wrt_no_addend
    mov rax, [rel_entry + 16]
    mov [rel_addend], rax
    jmp .wrt_resolve
.wrt_no_addend:
    mov qword [rel_addend], 0
.wrt_resolve:
    call resolve_relocation_symbol
    cmp byte [rel_json_mode], 0
    jne .wrt_emit_json
    call emit_relocation_text
    jmp .wrt_next_entry
.wrt_emit_json:
    call emit_relocation_json
.wrt_next_entry:
    inc qword [rel_entry_index]
    jmp .wrt_entry_loop
.wrt_entries_done:
    cmp byte [rel_json_mode], 0
    je .wrt_next
    PRINT j_rbrack
    PRINT j_rbrace
.wrt_next:
    inc r13
    jmp .wrt_scan
.wrt_done:
    ret

load_relocation_symbols:
    mov byte [rel_symtab_valid], 0
    mov byte [rel_str_valid], 0
    mov qword [dynstr_len], 0
    mov qword [sym_entry_count], 0
    mov eax, dword [rel_table_link]
    test eax, eax
    jz .lrs_done
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .lrs_done
    movzx ecx, word [ehdr + E_SHENTSIZE]
    imul rax, rcx
    add rax, [ehdr + E_SHOFF]
    jc .lrs_done
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    mov eax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jl .lrs_done
    mov eax, dword [shdr + SH_TYPE]
    cmp eax, 2                    ; SHT_SYMTAB
    je .lrs_save_table
    cmp eax, 11                   ; SHT_DYNSYM
    jne .lrs_done
.lrs_save_table:
    mov rax, [shdr + SH_OFFSET]
    mov [sym_table_offset], rax
    mov rax, [shdr + SH_SIZE]
    mov [sym_table_size], rax
    mov rax, [shdr + SH_ENTSIZE]
    mov [sym_table_entsize], rax
    mov eax, dword [shdr + SH_LINK]
    mov [sym_table_link], eax
    mov rax, [sym_table_entsize]
    cmp rax, 24
    jb .lrs_done
    mov rax, [sym_table_offset]
    add rax, [sym_table_size]
    jc .lrs_done
    cmp rax, [filesize]
    ja .lrs_done
    mov rax, [sym_table_size]
    xor edx, edx
    div qword [sym_table_entsize]
    test rdx, rdx
    jnz .lrs_done
    mov [sym_entry_count], rax
    mov byte [rel_symtab_valid], 1

    mov eax, dword [sym_table_link]
    test eax, eax
    jz .lrs_done
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jae .lrs_done
    call load_dynstr
    cmp dword [shdr + SH_TYPE], 3 ; SHT_STRTAB
    jne .lrs_bad_strtab
    mov byte [rel_str_valid], 1
    ret
.lrs_bad_strtab:
    mov qword [dynstr_len], 0
.lrs_done:
    ret

resolve_relocation_symbol:
    lea rax, [rel_unresolved]
    mov [rel_symbol_name], rax
    mov byte [rel_symbol_state], 0
    cmp byte [rel_symtab_valid], 0
    je .rrs_done
    cmp dword [rel_symbol_index], 0
    jne .rrs_nonzero
    lea rax, [rel_no_symbol]
    mov [rel_symbol_name], rax
    mov byte [rel_symbol_state], 2
    ret
.rrs_nonzero:
    cmp byte [rel_str_valid], 0
    je .rrs_done
    mov eax, dword [rel_symbol_index]
    cmp rax, [sym_entry_count]
    jae .rrs_done
    mul qword [sym_table_entsize]
    test rdx, rdx
    jnz .rrs_done
    add rax, [sym_table_offset]
    jc .rrs_done
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [syment]
    mov edx, 24
    mov eax, SYS_READ
    syscall
    cmp rax, 24
    jl .rrs_done
    mov eax, dword [syment]
    call dynstr_name_ptr
    mov [rel_symbol_name], rsi
    mov byte [rel_symbol_state], 1
.rrs_done:
    ret

emit_relocation_text_header:
    PRINT rel_table_pre
    mov rsi, [rel_table_name]
    call print_cstr
    PRINT rel_table_mid
    mov rax, [rel_table_index]
    call print_dec
    PRINT rel_kind_mid
    cmp dword [rel_table_type], 4
    jne .erth_rel
    lea rsi, [rel_kind_rela]
    jmp .erth_kind
.erth_rel:
    lea rsi, [rel_kind_rel]
.erth_kind:
    call print_cstr
    PRINT rel_target_mid
    cmp byte [rel_target_valid], 0
    je .erth_no_target
    mov rsi, [rel_target_name]
    call print_cstr
    jmp .erth_count
.erth_no_target:
    PRINT rel_target_none
.erth_count:
    PRINT rel_count_mid
    mov rax, [rel_entry_count]
    call print_dec
    PRINT rel_entries_end
    PRINT rel_colhdr
    cmp byte [rel_table_valid], 0
    jne .erth_symtab
    PRINT rel_bad_meta
.erth_symtab:
    cmp byte [rel_symtab_valid], 0
    jne .erth_strtab
    PRINT rel_bad_symtab
.erth_strtab:
    cmp byte [rel_str_valid], 0
    jne .erth_done
    PRINT rel_bad_strtab
.erth_done:
    ret

emit_relocation_json_header:
    cmp byte [rel_table_first], 1
    je .erjh_first
    PRINT j_comma
.erjh_first:
    mov byte [rel_table_first], 0
    PRINT j_lbrace
    PRINT jk_index
    mov rax, [rel_table_index]
    call print_dec
    PRINT j_comma
    PRINT jk_name
    mov rsi, [rel_table_name]
    call jstr
    PRINT j_comma
    PRINT jk_kind
    cmp dword [rel_table_type], 4
    jne .erjh_rel
    lea rsi, [rel_kind_rela]
    jmp .erjh_kind
.erjh_rel:
    lea rsi, [rel_kind_rel]
.erjh_kind:
    call jname
    PRINT j_comma
    PRINT jk_target_index
    mov eax, dword [rel_target_index]
    call print_dec
    PRINT j_comma
    PRINT jk_target_name
    cmp byte [rel_target_valid], 0
    je .erjh_no_target
    mov rsi, [rel_target_name]
    call jstr
    jmp .erjh_count
.erjh_no_target:
    PRINT j_null
.erjh_count:
    PRINT j_comma
    PRINT jk_entry_count
    mov rax, [rel_entry_count]
    call print_dec
    PRINT j_comma
    PRINT jk_valid
    cmp byte [rel_table_valid], 0
    je .erjh_invalid
    PRINT j_true
    jmp .erjh_symbols
.erjh_invalid:
    PRINT j_false
.erjh_symbols:
    PRINT j_comma
    PRINT jk_symbol_table_valid
    cmp byte [rel_symtab_valid], 0
    je .erjh_no_symtab
    PRINT j_true
    jmp .erjh_strings
.erjh_no_symtab:
    PRINT j_false
.erjh_strings:
    PRINT j_comma
    PRINT jk_strings_valid
    cmp byte [rel_str_valid], 0
    je .erjh_no_strings
    PRINT j_true
    jmp .erjh_relocations
.erjh_no_strings:
    PRINT j_false
.erjh_relocations:
    PRINT j_comma
    PRINT jk_relocations
    PRINT j_lbrack
    ret

emit_relocation_text:
    PRINT two_spaces
    mov rax, [rel_offset]
    mov ecx, 19
    call pfield_hex
    mov eax, dword [rel_type_id]
    call relocation_type_name
    mov rsi, rax
    mov ecx, 34
    call print_cstr_pad
    mov eax, dword [rel_type_id]
    mov ecx, 8
    call pfield_dec
    mov eax, dword [rel_symbol_index]
    mov ecx, 8
    call pfield_dec
    mov rsi, [rel_symbol_name]
    mov ecx, 32
    call print_cstr_pad
    cmp dword [rel_table_type], 4
    jne .ert_no_addend
    mov rax, [rel_addend]
    call print_signed
    jmp .ert_end
.ert_no_addend:
    PRINT rel_minus
.ert_end:
    PRINT nl
    ret

emit_relocation_json:
    cmp byte [rel_item_first], 1
    je .erj_first
    PRINT j_comma
.erj_first:
    mov byte [rel_item_first], 0
    PRINT j_lbrace
    PRINT jk_offset
    mov rax, [rel_offset]
    call jhex
    PRINT j_comma
    PRINT jk_type
    mov eax, dword [rel_type_id]
    call relocation_type_name
    mov rsi, rax
    call jname
    PRINT j_comma
    PRINT jk_type_id
    mov eax, dword [rel_type_id]
    call print_dec
    PRINT j_comma
    PRINT jk_symbol_index
    mov eax, dword [rel_symbol_index]
    call print_dec
    PRINT j_comma
    PRINT jk_symbol_name
    cmp byte [rel_symbol_state], 1
    jne .erj_no_symbol
    mov rsi, [rel_symbol_name]
    call jstr
    jmp .erj_addend
.erj_no_symbol:
    PRINT j_null
.erj_addend:
    PRINT j_comma
    PRINT jk_addend
    cmp dword [rel_table_type], 4
    jne .erj_no_addend
    mov rax, [rel_addend]
    call print_signed
    jmp .erj_end
.erj_no_addend:
    PRINT j_null
.erj_end:
    PRINT j_rbrace
    ret

relocation_type_name:
    cmp word [ehdr + E_MACHINE], 62
    jne .rtn_other
    cmp eax, 0
    je .rtn_none
    cmp eax, 1
    je .rtn_64
    cmp eax, 2
    je .rtn_pc32
    cmp eax, 3
    je .rtn_got32
    cmp eax, 4
    je .rtn_plt32
    cmp eax, 5
    je .rtn_copy
    cmp eax, 6
    je .rtn_glob_dat
    cmp eax, 7
    je .rtn_jump_slot
    cmp eax, 8
    je .rtn_relative
    cmp eax, 9
    je .rtn_gotpc_rel
    cmp eax, 10
    je .rtn_32
    cmp eax, 11
    je .rtn_32s
    cmp eax, 12
    je .rtn_16
    cmp eax, 13
    je .rtn_pc16
    cmp eax, 14
    je .rtn_8
    cmp eax, 15
    je .rtn_pc8
    cmp eax, 16
    je .rtn_dtpmod64
    cmp eax, 17
    je .rtn_dtpoff64
    cmp eax, 18
    je .rtn_tpoff64
    cmp eax, 19
    je .rtn_tls_gd
    cmp eax, 20
    je .rtn_tls_ld
    cmp eax, 21
    je .rtn_dtpoff32
    cmp eax, 22
    je .rtn_gottpoff
    cmp eax, 23
    je .rtn_tpoff32
    cmp eax, 24
    je .rtn_pc64
    cmp eax, 25
    je .rtn_gotoff64
    cmp eax, 26
    je .rtn_gotpc32
    cmp eax, 27
    je .rtn_got64
    cmp eax, 28
    je .rtn_gotpcrel64
    cmp eax, 29
    je .rtn_gotpc64
    cmp eax, 30
    je .rtn_gotplt64
    cmp eax, 31
    je .rtn_pltoff64
    cmp eax, 32
    je .rtn_size32
    cmp eax, 33
    je .rtn_size64
    cmp eax, 34
    je .rtn_gotpc32_tlsdesc
    cmp eax, 35
    je .rtn_tlsdesc_call
    cmp eax, 36
    je .rtn_tlsdesc
    cmp eax, 37
    je .rtn_irelative
    cmp eax, 38
    je .rtn_relative64
    cmp eax, 41
    je .rtn_gotpcrelx
    cmp eax, 42
    je .rtn_rex_gotpcrelx
    lea rax, [rel_type_unknown]
    ret
.rtn_other:
    lea rax, [rel_type_other]
    ret
.rtn_none:
    lea rax, [rt_none]
    ret
.rtn_64:
    lea rax, [rt_64]
    ret
.rtn_pc32:
    lea rax, [rt_pc32]
    ret
.rtn_got32:
    lea rax, [rt_got32]
    ret
.rtn_plt32:
    lea rax, [rt_plt32]
    ret
.rtn_copy:
    lea rax, [rt_copy]
    ret
.rtn_glob_dat:
    lea rax, [rt_glob_dat]
    ret
.rtn_jump_slot:
    lea rax, [rt_jump_slot]
    ret
.rtn_relative:
    lea rax, [rt_relative]
    ret
.rtn_gotpc_rel:
    lea rax, [rt_gotpc_rel]
    ret
.rtn_32:
    lea rax, [rt_32]
    ret
.rtn_32s:
    lea rax, [rt_32s]
    ret
.rtn_16:
    lea rax, [rt_16]
    ret
.rtn_pc16:
    lea rax, [rt_pc16]
    ret
.rtn_8:
    lea rax, [rt_8]
    ret
.rtn_pc8:
    lea rax, [rt_pc8]
    ret
.rtn_dtpmod64:
    lea rax, [rt_dtpmod64]
    ret
.rtn_dtpoff64:
    lea rax, [rt_dtpoff64]
    ret
.rtn_tpoff64:
    lea rax, [rt_tpoff64]
    ret
.rtn_tls_gd:
    lea rax, [rt_tls_gd]
    ret
.rtn_tls_ld:
    lea rax, [rt_tls_ld]
    ret
.rtn_dtpoff32:
    lea rax, [rt_dtpoff32]
    ret
.rtn_gottpoff:
    lea rax, [rt_gottpoff]
    ret
.rtn_tpoff32:
    lea rax, [rt_tpoff32]
    ret
.rtn_pc64:
    lea rax, [rt_pc64]
    ret
.rtn_gotoff64:
    lea rax, [rt_gotoff64]
    ret
.rtn_gotpc32:
    lea rax, [rt_gotpc32]
    ret
.rtn_got64:
    lea rax, [rt_got64]
    ret
.rtn_gotpcrel64:
    lea rax, [rt_gotpcrel64]
    ret
.rtn_gotpc64:
    lea rax, [rt_gotpc64]
    ret
.rtn_gotplt64:
    lea rax, [rt_gotplt64]
    ret
.rtn_pltoff64:
    lea rax, [rt_pltoff64]
    ret
.rtn_size32:
    lea rax, [rt_size32]
    ret
.rtn_size64:
    lea rax, [rt_size64]
    ret
.rtn_gotpc32_tlsdesc:
    lea rax, [rt_gotpc32_tlsdesc]
    ret
.rtn_tlsdesc_call:
    lea rax, [rt_tlsdesc_call]
    ret
.rtn_tlsdesc:
    lea rax, [rt_tlsdesc]
    ret
.rtn_irelative:
    lea rax, [rt_irelative]
    ret
.rtn_relative64:
    lea rax, [rt_relative64]
    ret
.rtn_gotpcrelx:
    lea rax, [rt_gotpcrelx]
    ret
.rtn_rex_gotpcrelx:
    lea rax, [rt_rex_gotpcrelx]
    ret

print_signed:
    test rax, rax
    jns .ps_positive
    push rax
    PRINT rel_minus
    pop rax
    neg rax
    call print_dec
    ret
.ps_positive:
    call print_dec
    ret

; ---------------------------------------------------------------------------
