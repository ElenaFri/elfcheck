; print_notes - decode ELF notes (readelf -n): GNU build-id, ABI tag and x86
;   feature properties, plus a generic owner/type/descsz line for anything else.
;   Prefers SHT_NOTE sections; falls back to PT_NOTE segments when a file has no
;   usable section headers.  Shares the record walker (scan_note_range) and the
;   bounds-checked readers (read_note_at / read_note_relative) with the hardening
;   scanner.  fd in r12.
; ---------------------------------------------------------------------------
print_notes:
    push r13
    push r14
    push r15
    PRINT notes_title
    mov qword [note_count], 0
    mov qword [note_ranges_seen], 0
    lea rax, [note_handler_print]
    mov [note_handler], rax

    mov rdi, r12               ; file size for bounds checks
    xor esi, esi
    mov edx, SEEK_END
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .pn_finish
    mov [filesize], rax

    call notes_scan_sections
    cmp qword [note_ranges_seen], 0
    jne .pn_finish             ; sections carried the notes; don't double-list
    call notes_scan_segments
.pn_finish:
    cmp qword [note_count], 0
    jne .pn_done
    PRINT notes_none
.pn_done:
    pop r15
    pop r14
    pop r13
    ret

; notes_scan_sections - run scan_note_range over every SHT_NOTE section.
notes_scan_sections:
    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .nss_done
    movzx r15d, word [ehdr + E_SHENTSIZE]
    cmp r15d, SHDR_SIZE
    jb .nss_done
    mov rax, r14
    mov rcx, r15
    mul rcx
    test rdx, rdx
    jnz .nss_done
    add rax, [ehdr + E_SHOFF]
    jc .nss_done
    cmp rax, [filesize]
    ja .nss_done
    xor r13, r13
.nss_loop:
    cmp r13, r14
    jae .nss_done
    mov rax, r13
    imul rax, r15
    add rax, [ehdr + E_SHOFF]
    jc .nss_done
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    call read_note_at
    cmp eax, 1
    jne .nss_done
    cmp dword [shdr + SH_TYPE], SHT_NOTE
    jne .nss_next
    inc qword [note_ranges_seen]
    mov rax, [shdr + SH_OFFSET]
    mov [note_range_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [note_range_size], rax
    call scan_note_range
.nss_next:
    inc r13
    jmp .nss_loop
.nss_done:
    ret

; notes_scan_segments - fallback: run scan_note_range over every PT_NOTE segment.
notes_scan_segments:
    movzx r14d, word [ehdr + E_PHNUM]
    test r14, r14
    jz .nsg_done
    movzx r15d, word [ehdr + E_PHENTSIZE]
    cmp r15d, PHDR_SIZE
    jb .nsg_done
    mov rax, r14
    mov rcx, r15
    mul rcx
    test rdx, rdx
    jnz .nsg_done
    add rax, [ehdr + E_PHOFF]
    jc .nsg_done
    cmp rax, [filesize]
    ja .nsg_done
    xor r13, r13
.nsg_loop:
    cmp r13, r14
    jae .nsg_done
    mov rax, r13
    imul rax, r15
    add rax, [ehdr + E_PHOFF]
    jc .nsg_done
    lea rsi, [phdr]
    mov edx, PHDR_SIZE
    call read_note_at
    cmp eax, 1
    jne .nsg_done
    cmp dword [phdr + P_TYPE], PT_NOTE
    jne .nsg_next
    mov rax, [phdr + P_OFFSET]
    mov [note_range_off], rax
    mov rax, [phdr + P_FILESZ]
    mov [note_range_size], rax
    call scan_note_range
.nsg_next:
    inc r13
    jmp .nsg_loop
.nsg_done:
    ret

; note_handler_print - per-record handler installed by print_notes.  Reads the
; record owner and description, then prints a decoded line.  Must not clobber
; note_cursor / note_record_end (the record walker needs them after this call).
note_handler_print:
    push rbx
    inc qword [note_count]
    call note_read_owner
    call note_stage_desc

    cmp dword [note_owner], 0x00554e47   ; "GNU\0"
    jne .generic
    mov eax, [note_type]
    cmp eax, NT_GNU_BUILD_ID
    je .build_id
    cmp eax, NT_GNU_ABI_TAG
    je .abi_tag
    cmp eax, NT_GNU_PROPERTY_TYPE_0
    je .property
    jmp .generic

.build_id:
    PRINT note_buildid_lbl
    xor ebx, ebx
.bid_loop:
    cmp rbx, [note_desc_staged]
    jae .bid_done
    lea rdx, [note_desc_buf]
    mov al, [rdx + rbx]
    call print_byte_hex
    inc rbx
    jmp .bid_loop
.bid_done:
    PRINT nl
    jmp .nhp_ret

.abi_tag:
    cmp qword [note_desc_staged], 16
    jb .generic
    PRINT note_abi_lbl
    mov eax, dword [note_desc_buf]       ; OS id
    call note_print_os
    mov eax, dword [note_desc_buf + 4]   ; major
    call print_dec
    PRINT note_dot
    mov eax, dword [note_desc_buf + 8]   ; minor
    call print_dec
    PRINT note_dot
    mov eax, dword [note_desc_buf + 12]  ; subminor
    call print_dec
    PRINT nl
    jmp .nhp_ret

.property:
    PRINT note_props_lbl
    call note_print_x86_features
    PRINT nl
    jmp .nhp_ret

.generic:
    PRINT note_owner_lbl
    lea rsi, [note_owner]
    call print_cstr
    PRINT note_type_lbl
    mov eax, [note_type]
    call print_hex
    PRINT note_descsz_lbl
    mov rax, [note_desc_size]
    call print_dec
    PRINT nl
.nhp_ret:
    pop rbx
    ret

; note_read_owner - copy the record name into note_owner (NUL-terminated),
; clamped to the buffer size.  Empty/invalid names leave an empty string.
note_read_owner:
    mov eax, [note_namesz]
    test eax, eax
    jz .nro_empty
    cmp eax, 35
    jbe .nro_len_ok
    mov eax, 35
.nro_len_ok:
    mov rcx, [note_cursor]
    add rcx, 12
    mov [note_rel], rcx
    mov [note_len], rax
    lea rsi, [note_owner]
    mov edx, eax
    call read_note_relative
    cmp eax, 1
    jne .nro_empty
    mov rax, [note_len]
    lea rsi, [note_owner]
    mov byte [rsi + rax], 0
    ret
.nro_empty:
    mov byte [note_owner], 0
    ret

; note_stage_desc - copy the record description into note_desc_buf, clamped to
; NOTE_DESC_CAP.  [note_desc_staged] holds the number of staged bytes (0 on none).
note_stage_desc:
    mov qword [note_desc_staged], 0
    mov rax, [note_desc_size]
    test rax, rax
    jz .nsd_done
    cmp rax, NOTE_DESC_CAP
    jbe .nsd_len_ok
    mov rax, NOTE_DESC_CAP
.nsd_len_ok:
    mov rcx, [note_desc_rel]
    mov [note_rel], rcx
    mov [note_len], rax
    lea rsi, [note_desc_buf]
    mov rdx, rax
    call read_note_relative
    cmp eax, 1
    jne .nsd_done
    mov rax, [note_len]
    mov [note_desc_staged], rax
.nsd_done:
    ret

; note_print_os - print the ABI-tag OS name for the id in eax (trailing space).
note_print_os:
    cmp eax, 0
    je .os_linux
    cmp eax, 1
    je .os_gnu
    cmp eax, 2
    je .os_solaris
    cmp eax, 3
    je .os_freebsd
    cmp eax, 4
    je .os_netbsd
    PRINT note_os_unknown
    ret
.os_linux:
    PRINT note_os_linux
    ret
.os_gnu:
    PRINT note_os_gnu
    ret
.os_solaris:
    PRINT note_os_solaris
    ret
.os_freebsd:
    PRINT note_os_freebsd
    ret
.os_netbsd:
    PRINT note_os_netbsd
    ret

; note_print_x86_features - print "x86 feature: " then the decoded X86_FEATURE_1_AND
; flags (IBT / SHSTK) from the staged GNU property description, or "none".
note_print_x86_features:
    push rbx
    PRINT note_x86_feat
    xor rbx, rbx               ; byte cursor into note_desc_buf
    lea r9, [note_desc_buf]    ; base pointer (avoids absolute relocations)
.nxf_loop:
    mov rax, rbx
    add rax, 8
    cmp rax, [note_desc_staged]
    ja .nxf_none
    mov eax, dword [r9 + rbx]       ; property type
    mov edx, dword [r9 + rbx + 4]   ; property datasz
    cmp eax, GNU_PROPERTY_X86_FEATURE_1_AND
    jne .nxf_adv
    cmp edx, 4
    jb .nxf_adv
    mov rax, rbx
    add rax, 12
    cmp rax, [note_desc_staged]
    ja .nxf_none
    mov eax, dword [r9 + rbx + 8]   ; feature flags
    jmp .nxf_flags
.nxf_adv:
    add edx, 7                 ; pad datasz up to 8 bytes
    and edx, -8
    add rbx, 8
    add rbx, rdx
    jmp .nxf_loop
.nxf_flags:
    mov ebx, eax               ; keep flags across the writes below
    xor r8d, r8d               ; items printed so far
    test ebx, GNU_PROPERTY_X86_FEATURE_1_IBT
    jz .nxf_shstk
    PRINT note_feat_ibt
    mov r8d, 1
.nxf_shstk:
    test ebx, GNU_PROPERTY_X86_FEATURE_1_SHSTK
    jz .nxf_flags_done
    test r8d, r8d
    jz .nxf_shstk_only
    PRINT note_comma_sp
.nxf_shstk_only:
    PRINT note_feat_shstk
    mov r8d, 1
.nxf_flags_done:
    test r8d, r8d
    jnz .nxf_ret
    PRINT note_feat_none       ; property present but no IBT/SHSTK bits set
.nxf_ret:
    pop rbx
    ret
.nxf_none:
    PRINT note_feat_none
    pop rbx
    ret
