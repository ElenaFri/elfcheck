; print_header - format and print the parsed ELF64 header from [ehdr]
; ---------------------------------------------------------------------------
print_header:
    PRINT hdr_title

    PRINT l_class
    movzx eax, byte [ehdr + EI_CLASS]
    call class_name
    mov rsi, rax
    call print_cstr
    PRINT nl

    PRINT l_data
    movzx eax, byte [ehdr + EI_DATA]
    call data_name
    mov rsi, rax
    call print_cstr
    PRINT nl

    PRINT l_version
    movzx eax, byte [ehdr + EI_VERSION]
    call print_dec
    PRINT nl

    PRINT l_osabi
    movzx eax, byte [ehdr + EI_OSABI]
    call osabi_name
    mov rsi, rax
    call print_cstr
    PRINT nl

    PRINT l_type
    movzx eax, word [ehdr + E_TYPE]
    call type_name
    mov rsi, rax
    call print_cstr
    PRINT nl

    PRINT l_machine
    movzx eax, word [ehdr + E_MACHINE]
    call machine_name
    mov rsi, rax
    call print_cstr
    PRINT nl

    PRINT l_entry
    mov rax, [ehdr + E_ENTRY]
    call print_hex
    PRINT nl

    PRINT l_phoff
    mov rax, [ehdr + E_PHOFF]
    call print_dec
    PRINT nl

    PRINT l_shoff
    mov rax, [ehdr + E_SHOFF]
    call print_dec
    PRINT nl

    PRINT l_flags
    mov eax, dword [ehdr + E_FLAGS]
    call print_hex
    PRINT nl

    PRINT l_ehsize
    movzx eax, word [ehdr + E_EHSIZE]
    call print_dec
    PRINT nl

    PRINT l_phentsize
    movzx eax, word [ehdr + E_PHENTSIZE]
    call print_dec
    PRINT nl

    PRINT l_phnum
    movzx eax, word [ehdr + E_PHNUM]
    call print_dec
    PRINT nl

    PRINT l_shentsize
    movzx eax, word [ehdr + E_SHENTSIZE]
    call print_dec
    PRINT nl

    PRINT l_shnum
    movzx eax, word [ehdr + E_SHNUM]
    call print_dec
    PRINT nl

    PRINT l_shstrndx
    movzx eax, word [ehdr + E_SHSTRNDX]
    call print_dec
    PRINT nl
    ret

; ---------------------------------------------------------------------------
; print_program_headers - iterate and display the program header table.
; Reads each entry from the file (fd in r12) using its own lseek+read so it
; works regardless of how much of the file was buffered.
; Registers: r12=fd (preserved), r13=index, r14=phnum (callee-saved style).
; ---------------------------------------------------------------------------
print_program_headers:
    movzx r14d, word [ehdr + E_PHNUM]
    test r14, r14
    jz .pph_ret

    PRINT ph_title
    call print_ph_colhdr
    xor r13, r13               ; i = 0
.pph_loop:
    cmp r13, r14
    jae .pph_ret

    movzx eax, word [ehdr + E_PHENTSIZE]
    imul rax, r13              ; i * phentsize
    add rax, [ehdr + E_PHOFF]  ; file offset of entry i

    mov rdi, r12               ; lseek(fd, offset, SEEK_SET)
    mov rsi, rax
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall

    mov rdi, r12               ; read(fd, phdr, PHDR_SIZE)
    lea rsi, [phdr]
    mov rdx, PHDR_SIZE
    mov rax, SYS_READ
    syscall
    cmp rax, PHDR_SIZE
    jl .pph_ret                ; short read -> stop

    call print_one_phdr
    inc r13
    jmp .pph_loop
.pph_ret:
    ret

; print the aligned column header row (same widths as the data rows)
print_ph_colhdr:
    PRINT two_spaces
    lea rsi, [col_idx]
    mov ecx, W_IDX
    call print_cstr_pad
    lea rsi, [col_type]
    mov ecx, W_TYPE
    call print_cstr_pad
    lea rsi, [col_flags]
    mov ecx, W_FLAGS
    call print_cstr_pad
    lea rsi, [col_offset]
    mov ecx, W_OFF
    call print_cstr_pad
    lea rsi, [col_vaddr]
    mov ecx, W_VADDR
    call print_cstr_pad
    lea rsi, [col_filesz]
    mov ecx, W_FILESZ
    call print_cstr_pad
    lea rsi, [col_memsz]
    mov ecx, W_MEMSZ
    call print_cstr_pad
    PRINT col_align
    PRINT nl
    ret

; print one program header entry from [phdr] as an aligned table row
print_one_phdr:
    PRINT two_spaces

    mov rax, r13               ; index
    mov ecx, W_IDX
    call pfield_dec

    mov eax, dword [phdr + P_TYPE]
    call phdr_type_name
    mov rsi, rax
    mov ecx, W_TYPE
    call print_cstr_pad

    mov eax, dword [phdr + P_FLAGS]
    call build_flags
    lea rsi, [flagbuf]
    mov ecx, W_FLAGS
    call print_cstr_pad

    mov rax, [phdr + P_OFFSET]
    mov ecx, W_OFF
    call pfield_hex

    mov rax, [phdr + P_VADDR]
    mov ecx, W_VADDR
    call pfield_hex

    mov rax, [phdr + P_FILESZ]
    mov ecx, W_FILESZ
    call pfield_hex

    mov rax, [phdr + P_MEMSZ]
    mov ecx, W_MEMSZ
    call pfield_hex

    mov rax, [phdr + P_ALIGN]  ; last column, no padding
    call print_hex

    PRINT nl
    ret

; build_flags - render p_flags (eax) into flagbuf as a NUL-terminated
;               3-char R/W/X string
build_flags:                   ; in: eax = flags
    test al, 4
    jz .nr
    mov byte [flagbuf + 0], 'R'
    jmp .w
.nr:
    mov byte [flagbuf + 0], '-'
.w:
    test al, 2
    jz .nw
    mov byte [flagbuf + 1], 'W'
    jmp .x
.nw:
    mov byte [flagbuf + 1], '-'
.x:
    test al, 1
    jz .nx
    mov byte [flagbuf + 2], 'X'
    jmp .emit
.nx:
    mov byte [flagbuf + 2], '-'
.emit:
    mov byte [flagbuf + 3], 0
    ret

; phdr_type_name - map p_type (eax) to a name pointer (rax)
phdr_type_name:
    cmp eax, 0
    je .null
    cmp eax, 1
    je .load
    cmp eax, 2
    je .dyn
    cmp eax, 3
    je .interp
    cmp eax, 4
    je .note
    cmp eax, 6
    je .phdr
    cmp eax, 7
    je .tls
    cmp eax, 0x6474e550
    je .ehframe
    cmp eax, 0x6474e551
    je .gnustack
    cmp eax, 0x6474e552
    je .gnurelro
    cmp eax, 0x6474e553
    je .gnuprop
    lea rax, [pt_unknown]
    ret
.null:     lea rax, [pt_null]
    ret
.load:     lea rax, [pt_load]
    ret
.dyn:      lea rax, [pt_dynamic]
    ret
.interp:   lea rax, [pt_interp]
    ret
.note:     lea rax, [pt_note]
    ret
.phdr:     lea rax, [pt_phdr]
    ret
.tls:      lea rax, [pt_tls]
    ret
.ehframe:  lea rax, [pt_ehframe]
    ret
.gnustack: lea rax, [pt_gnustack]
    ret
.gnurelro: lea rax, [pt_gnurelro]
    ret
.gnuprop:  lea rax, [pt_gnuprop]
    ret

; ---------------------------------------------------------------------------
; print_section_headers - iterate and display the section header table.
; First loads the section-name string table, then prints one row per section.
; Registers: r12=fd (preserved), r13=index, r14=shnum.
; ---------------------------------------------------------------------------
print_section_headers:
    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .psh_ret

    call load_shstrtab
    PRINT sh_title
    call print_sh_colhdr
    xor r13, r13               ; i = 0
.psh_loop:
    cmp r13, r14
    jae .psh_ret

    movzx eax, word [ehdr + E_SHENTSIZE]
    imul rax, r13              ; i * shentsize
    add rax, [ehdr + E_SHOFF]  ; file offset of entry i

    mov rdi, r12               ; lseek(fd, offset, SEEK_SET)
    mov rsi, rax
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall

    mov rdi, r12               ; read(fd, shdr, SHDR_SIZE)
    lea rsi, [shdr]
    mov rdx, SHDR_SIZE
    mov rax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jl .psh_ret                ; short read -> stop

    call print_one_shdr
    inc r13
    jmp .psh_loop
.psh_ret:
    ret

; ---------------------------------------------------------------------------
; print_section_to_segment_mapping - print the "Section to Segment mapping:"
;   table (readelf -l parity).  Needs [shdr] and [phdr] filled, and load_shstrtab.
;   Registers: r12=fd (preserved), r13=segment index, r14=section index,
;             r15=section count, rbx=segment count.
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; print_section_to_segment_mapping - print the "Section to Segment mapping:"
;   table (readelf -l parity).  Needs [shdr] and [phdr] filled, and load_shstrtab.
;   Registers: r12=fd (preserved), r13=segment index, r14=section index,
;             r15=section count, rbx=segment count.
; ---------------------------------------------------------------------------
print_section_to_segment_mapping:
    movzx r15d, word [ehdr + E_SHNUM]
    test r15, r15
    jz .pssm_ret
    movzx ebx, word [ehdr + E_PHNUM]
    test ebx, ebx
    jz .pssm_ret
    call load_shstrtab
    PRINT s2s_title
    xor r13, r13               ; segment index
.pssm_seg_loop:
    cmp r13, rbx
    jae .pssm_ret
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
    jl .pssm_ret
    PRINT s2s_sep
    mov rax, r13
    mov ecx, 2
    call pfield_dec2
    PRINT s2s_sep2
    xor r14, r14               ; section index
.pssm_sec_loop:
    cmp r14, r15
    jae .pssm_next_seg
    movzx eax, word [ehdr + E_SHENTSIZE]
    imul rax, r14
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
    jl .pssm_next_seg
    mov eax, dword [shdr + SH_TYPE]
    cmp eax, SHT_NULL
    je .pssm_skip_sec
    ; Check if section is in segment (addr or offset)
    mov rax, [shdr + SH_ADDR]
    mov rcx, [shdr + SH_FLAGS]
    test rcx, SHF_ALLOC
    jnz .pssm_check_addr
    ; For non-ALLOC sections, use offset
    mov rax, [shdr + SH_OFFSET]
    mov rcx, [phdr + P_OFFSET]
    mov rdx, [phdr + P_FILESZ]
    add rcx, rdx
    cmp rax, [phdr + P_OFFSET]
    jb .pssm_skip_sec
    cmp rax, rcx
    jae .pssm_skip_sec
    jmp .pssm_print_sec
.pssm_check_addr:
    mov rcx, [phdr + P_VADDR]
    mov rdx, [phdr + P_MEMSZ]
    add rcx, rdx
    cmp rax, [phdr + P_VADDR]
    jb .pssm_check_offset
    cmp rax, rcx
    jae .pssm_check_offset
    jmp .pssm_print_sec
.pssm_check_offset:
    mov rax, [shdr + SH_OFFSET]
    mov rcx, [phdr + P_OFFSET]
    mov rdx, [phdr + P_FILESZ]
    add rcx, rdx
    cmp rax, [phdr + P_OFFSET]
    jb .pssm_skip_sec
    cmp rax, rcx
    jae .pssm_skip_sec
.pssm_print_sec:
    call section_name_ptr
    call print_cstr
    PRINT one_space
.pssm_skip_sec:
    inc r14
    jmp .pssm_sec_loop
.pssm_next_seg:
    PRINT nl
    inc r13
    jmp .pssm_seg_loop
.pssm_ret:
    ret
;                 [strtab]; number of bytes stored in [strtab_size] (0 on none)
load_shstrtab:
    mov qword [strtab_size], 0
    movzx eax, word [ehdr + E_SHSTRNDX]
    test eax, eax
    jz .lss_ret                ; no string table

    movzx ecx, word [ehdr + E_SHENTSIZE]
    imul rax, rcx              ; shstrndx * shentsize
    add rax, [ehdr + E_SHOFF]

    mov rdi, r12               ; lseek to that section header
    mov rsi, rax
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall

    mov rdi, r12               ; read its 64-byte header into shdr
    lea rsi, [shdr]
    mov rdx, SHDR_SIZE
    mov rax, SYS_READ
    syscall
    cmp rax, SHDR_SIZE
    jl .lss_ret

    mov rdx, [shdr + SH_SIZE]  ; clamp request to STRTAB_CAP
    cmp rdx, STRTAB_CAP
    jbe .lss_cap
    mov rdx, STRTAB_CAP
.lss_cap:
    mov rdi, r12               ; lseek to the table data
    mov rsi, [shdr + SH_OFFSET]
    push rdx
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
    pop rdx

    mov rdi, r12               ; read the table bytes
    lea rsi, [strtab]
    mov rax, SYS_READ
    syscall
    test rax, rax
    js .lss_ret                ; error -> size stays 0
    mov [strtab_size], rax
    lea rsi, [strtab]          ; guarantee NUL termination
    mov byte [rsi + rax], 0
.lss_ret:
    ret

; section_name_ptr - out: rsi -> name string for the current [shdr]
section_name_ptr:
    mov eax, dword [shdr + SH_NAME]
    cmp rax, [strtab_size]
    jae .sn_empty
    lea rsi, [strtab]
    add rsi, rax
    ret
.sn_empty:
    lea rsi, [empty_str]
    ret

; print the aligned section-table column header row
print_sh_colhdr:
    PRINT two_spaces
    lea rsi, [col_idx]
    mov ecx, WS_IDX
    call print_cstr_pad
    lea rsi, [col_name]
    mov ecx, WS_NAME
    call print_cstr_pad
    lea rsi, [col_type]
    mov ecx, WS_TYPE
    call print_cstr_pad
    lea rsi, [col_flags]
    mov ecx, WS_FLAGS
    call print_cstr_pad
    lea rsi, [col_addr]
    mov ecx, WS_ADDR
    call print_cstr_pad
    lea rsi, [col_offset]
    mov ecx, WS_OFFSET
    call print_cstr_pad
    lea rsi, [col_size]
    mov ecx, WS_SIZE
    call print_cstr_pad
    PRINT col_align
    PRINT nl
    ret

; print one section header entry from [shdr] as an aligned table row
print_one_shdr:
    PRINT two_spaces

    mov rax, r13               ; index
    mov ecx, WS_IDX
    call pfield_dec

    call section_name_ptr      ; rsi -> name
    mov ecx, WS_NAME
    call print_cstr_pad

    mov eax, dword [shdr + SH_TYPE]
    call shdr_type_name
    mov rsi, rax
    mov ecx, WS_TYPE
    call print_cstr_pad

    mov rax, [shdr + SH_FLAGS]
    call build_sh_flags
    lea rsi, [shflagbuf]
    mov ecx, WS_FLAGS
    call print_cstr_pad

    mov rax, [shdr + SH_ADDR]
    mov ecx, WS_ADDR
    call pfield_hex

    mov rax, [shdr + SH_OFFSET]
    mov ecx, WS_OFFSET
    call pfield_hex

    mov rax, [shdr + SH_SIZE]
    mov ecx, WS_SIZE
    call pfield_hex

    mov rax, [shdr + SH_ADDRALIGN]  ; last column, no padding
    call print_hex

    PRINT nl
    ret

; build_sh_flags - render sh_flags (rax) into shflagbuf as NUL-terminated
;                  readelf-style letters (W A X M S I L G T)
build_sh_flags:                ; in: rax = flags
    lea rdi, [shflagbuf]
    test rax, 0x1
    jz .a
    mov byte [rdi], 'W'
    inc rdi
.a:
    test rax, 0x2
    jz .x
    mov byte [rdi], 'A'
    inc rdi
.x:
    test rax, 0x4
    jz .m
    mov byte [rdi], 'X'
    inc rdi
.m:
    test rax, 0x10
    jz .s
    mov byte [rdi], 'M'
    inc rdi
.s:
    test rax, 0x20
    jz .i
    mov byte [rdi], 'S'
    inc rdi
.i:
    test rax, 0x40
    jz .l
    mov byte [rdi], 'I'
    inc rdi
.l:
    test rax, 0x80
    jz .g
    mov byte [rdi], 'L'
    inc rdi
.g:
    test rax, 0x200
    jz .t
    mov byte [rdi], 'G'
    inc rdi
.t:
    test rax, 0x400
    jz .bf_done
    mov byte [rdi], 'T'
    inc rdi
.bf_done:
    mov byte [rdi], 0
    ret

; shdr_type_name - map sh_type (eax) to a name pointer (rax)
shdr_type_name:
    cmp eax, 0
    je .null
    cmp eax, 1
    je .progbits
    cmp eax, 2
    je .symtab
    cmp eax, 3
    je .strtab
    cmp eax, 4
    je .rela
    cmp eax, 5
    je .hash
    cmp eax, 6
    je .dynamic
    cmp eax, 7
    je .note
    cmp eax, 8
    je .nobits
    cmp eax, 9
    je .rel
    cmp eax, 11
    je .dynsym
    cmp eax, 14
    je .init_arr
    cmp eax, 15
    je .fini_arr
    cmp eax, 16
    je .preinit
    cmp eax, 17
    je .group
    cmp eax, 0x6ffffff6
    je .gnu_hash
    cmp eax, 0x6ffffffd
    je .verdef
    cmp eax, 0x6ffffffe
    je .verneed
    cmp eax, 0x6fffffff
    je .versym
    lea rax, [sht_unknown]
    ret
.null:     lea rax, [sht_null]
    ret
.progbits: lea rax, [sht_progbits]
    ret
.symtab:   lea rax, [sht_symtab]
    ret
.strtab:   lea rax, [sht_strtab]
    ret
.rela:     lea rax, [sht_rela]
    ret
.hash:     lea rax, [sht_hash]
    ret
.dynamic:  lea rax, [sht_dynamic]
    ret
.note:     lea rax, [sht_note]
    ret
.nobits:   lea rax, [sht_nobits]
    ret
.rel:      lea rax, [sht_rel]
    ret
.dynsym:   lea rax, [sht_dynsym]
    ret
.init_arr: lea rax, [sht_init_arr]
    ret
.fini_arr: lea rax, [sht_fini_arr]
    ret
.preinit:  lea rax, [sht_preinit]
    ret
.group:    lea rax, [sht_group]
    ret
.gnu_hash: lea rax, [sht_gnu_hash]
    ret
.verdef:   lea rax, [sht_verdef]
    ret
.verneed:  lea rax, [sht_verneed]
    ret
.versym:   lea rax, [sht_versym]
    ret

; ---------------------------------------------------------------------------
; validate_structure - sanity-check header fields, segment and section file
; ranges against the real file size; report every problem and count them in
; [issues].  Uses fd in r12; r13=index, r14=count.
; ---------------------------------------------------------------------------
validate_structure:
    VP val_title
    mov qword [issues], 0

    mov rdi, r12               ; file size = lseek(fd, 0, SEEK_END)
    xor esi, esi
    mov edx, SEEK_END
    mov rax, SYS_LSEEK
    syscall
    mov [filesize], rax
    test rax, rax
    jns .size_ok
    mov rax, 0x7fffffffffffffff   ; error: don't flag everything
    mov [filesize], rax
.size_ok:

    ; --- ELF header version fields must be current ---
    movzx eax, byte [ehdr + EI_VERSION]
    cmp eax, EV_CURRENT
    je .chk_e_version
    VP val_mark
    VP m_eiversion
    movzx eax, byte [ehdr + EI_VERSION]
    call vdec
    VP m_exp1
    VP nl
    inc qword [issues]
.chk_e_version:
    cmp dword [ehdr + E_VERSION], EV_CURRENT
    je .chk_ehsize
    VP val_mark
    VP m_eversion
    mov eax, dword [ehdr + E_VERSION]
    call vdec
    VP m_exp1
    VP nl
    inc qword [issues]

    ; --- e_ehsize == 64 ---
.chk_ehsize:
    movzx eax, word [ehdr + E_EHSIZE]
    cmp eax, EHDR_SIZE
    je .chk_phentsize
    VP val_mark
    VP m_ehsize
    movzx eax, word [ehdr + E_EHSIZE]
    call vdec
    VP m_exp64
    VP nl
    inc qword [issues]
.chk_phentsize:
    ; --- e_phentsize == 56 when phnum > 0 ---
    movzx eax, word [ehdr + E_PHNUM]
    test eax, eax
    jz .chk_shentsize
    movzx eax, word [ehdr + E_PHENTSIZE]
    cmp eax, PHDR_SIZE
    je .chk_shentsize
    VP val_mark
    VP m_phentsize
    movzx eax, word [ehdr + E_PHENTSIZE]
    call vdec
    VP m_exp56
    VP nl
    inc qword [issues]
.chk_shentsize:
    ; --- e_shentsize == 64 when shnum > 0 ---
    movzx eax, word [ehdr + E_SHNUM]
    test eax, eax
    jz .chk_shstrndx
    movzx eax, word [ehdr + E_SHENTSIZE]
    cmp eax, SHDR_SIZE
    je .chk_shstrndx
    VP val_mark
    VP m_shentsize
    movzx eax, word [ehdr + E_SHENTSIZE]
    call vdec
    VP m_exp64
    VP nl
    inc qword [issues]
.chk_shstrndx:
    ; --- e_shstrndx < shnum (ignore SHN_XINDEX 0xffff) ---
    movzx eax, word [ehdr + E_SHNUM]
    test eax, eax
    jz .chk_phtab
    movzx eax, word [ehdr + E_SHSTRNDX]
    cmp eax, 0xffff
    je .chk_phtab
    movzx ecx, word [ehdr + E_SHNUM]
    cmp eax, ecx
    jb .chk_phtab
    VP val_mark
    VP m_shstrndx
    movzx eax, word [ehdr + E_SHSTRNDX]
    call vdec
    VP m_oorange
    movzx eax, word [ehdr + E_SHNUM]
    call vdec
    VP m_rparen
    VP nl
    inc qword [issues]
.chk_phtab:
    ; --- program header table within file ---
    movzx eax, word [ehdr + E_PHNUM]
    test eax, eax
    jz .chk_shtab
    movzx ecx, word [ehdr + E_PHENTSIZE]
    imul rax, rcx
    add rax, [ehdr + E_PHOFF]
    jc .phtab_bad
    cmp rax, [filesize]
    jbe .chk_shtab
.phtab_bad:
    VP val_mark
    VP m_phtab
    inc qword [issues]
.chk_shtab:
    ; --- section header table within file ---
    movzx eax, word [ehdr + E_SHNUM]
    test eax, eax
    jz .chk_segments
    movzx ecx, word [ehdr + E_SHENTSIZE]
    imul rax, rcx
    add rax, [ehdr + E_SHOFF]
    jc .shtab_bad
    cmp rax, [filesize]
    jbe .chk_segments
.shtab_bad:
    VP val_mark
    VP m_shtab
    inc qword [issues]
.chk_segments:
    ; --- per-segment file range checks ---
    movzx r14d, word [ehdr + E_PHNUM]
    xor r13, r13
.vp_loop:
    cmp r13, r14
    jae .chk_sections
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
    jl .chk_sections
    ; offset + filesz <= filesize ?
    mov rax, [phdr + P_OFFSET]
    add rax, [phdr + P_FILESZ]
    jc .vp_past
    cmp rax, [filesize]
    jbe .vp_memcheck
.vp_past:
    VP val_mark
    VP m_seg
    mov rax, r13
    call vdec
    VP m_past_off
    mov rax, [phdr + P_OFFSET]
    call vhex
    VP m_filesz
    mov rax, [phdr + P_FILESZ]
    call vhex
    VP m_rparen
    VP nl
    inc qword [issues]
.vp_memcheck:
    ; filesz <= memsz ?
    mov rax, [phdr + P_FILESZ]
    cmp rax, [phdr + P_MEMSZ]
    jbe .vp_next
    VP val_mark
    VP m_seg
    mov rax, r13
    call vdec
    VP m_fmgt
    VP nl
    inc qword [issues]
.vp_next:
    inc r13
    jmp .vp_loop
.chk_sections:
    ; --- per-section file range checks ---
    movzx r14d, word [ehdr + E_SHNUM]
    xor r13, r13
.vs_loop:
    cmp r13, r14
    jae .summary
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
    jl .summary
    ; skip SHT_NULL (0) and SHT_NOBITS (8): no file content
    mov eax, dword [shdr + SH_TYPE]
    cmp eax, 0
    je .vs_next
    cmp eax, 8
    je .vs_next
    mov rax, [shdr + SH_OFFSET]
    add rax, [shdr + SH_SIZE]
    jc .vs_past
    cmp rax, [filesize]
    jbe .vs_next
.vs_past:
    VP val_mark
    VP m_sect
    mov rax, r13
    call vdec
    VP m_past_off
    mov rax, [shdr + SH_OFFSET]
    call vhex
    VP m_size
    mov rax, [shdr + SH_SIZE]
    call vhex
    VP m_rparen
    VP nl
    inc qword [issues]
.vs_next:
    inc r13
    jmp .vs_loop
.summary:
    cmp qword [issues], 0
    jne .some
    VP val_ok
    ret
.some:
    VP two_spaces
    mov rax, [issues]
    call vdec
    VP m_issues
    ret

; ---------------------------------------------------------------------------
; check_security - inspect segment permissions and stack executability.
; Flags W^X (writable + executable) segments and the PT_GNU_STACK state, and
; counts findings in [warnings].  Uses VP/vdec so it doubles as a silent
; counter for the JSON path.  Uses fd in r12; r13=index, r14=phnum.
; ---------------------------------------------------------------------------
check_security:
    VP sec_title
    mov qword [warnings], 0
    mov qword [sec_wx], 0
    mov qword [sec_wxsect], 0
    mov byte [sec_stack], 0            ; assume GNU_STACK absent
    mov byte [sec_entry_ok], 0         ; assume entry not in an exec segment
    ; --- phase 1: program headers ---
    movzx r14d, word [ehdr + E_PHNUM]
    test r14, r14
    jz .entry_check
    xor r13, r13
.cs_loop:
    cmp r13, r14
    jae .entry_check
    movzx eax, word [ehdr + E_PHENTSIZE]
    imul rax, r13
    add rax, [ehdr + E_PHOFF]
    mov rdi, r12                       ; lseek(fd, offset, SEEK_SET)
    mov rsi, rax
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
    mov rdi, r12                       ; read(fd, phdr, PHDR_SIZE)
    lea rsi, [phdr]
    mov rdx, PHDR_SIZE
    mov rax, SYS_READ
    syscall
    cmp rax, PHDR_SIZE
    jl .entry_check                   ; short read -> stop scanning
    ; --- PT_GNU_STACK tracking ---
    mov eax, dword [phdr + P_TYPE]
    cmp eax, PT_GNU_STACK
    jne .cs_wx
    mov byte [sec_stack], 1            ; present, non-executable
    test byte [phdr + P_FLAGS], PF_X
    jz .cs_wx
    mov byte [sec_stack], 2            ; present and executable
.cs_wx:
    ; --- W^X violation: a loadable (PT_LOAD) segment with both W and X ---
    cmp dword [phdr + P_TYPE], 1       ; PT_LOAD only; GNU_STACK handled below
    jne .cs_entry
    mov al, byte [phdr + P_FLAGS]
    and al, (PF_W | PF_X)
    cmp al, (PF_W | PF_X)
    jne .cs_entry
    VP s_wx_pre
    mov rax, r13
    call vdec
    VP s_wx_post
    inc qword [warnings]
    inc qword [sec_wx]
.cs_entry:
    ; --- entry-point coverage: PT_LOAD + X whose range contains e_entry ---
    cmp dword [phdr + P_TYPE], 1
    jne .cs_next
    test byte [phdr + P_FLAGS], PF_X
    jz .cs_next
    mov rax, [ehdr + E_ENTRY]
    cmp rax, [phdr + P_VADDR]
    jb .cs_next
    mov rcx, [phdr + P_VADDR]
    add rcx, [phdr + P_MEMSZ]
    cmp rax, rcx
    jae .cs_next
    mov byte [sec_entry_ok], 1
.cs_next:
    inc r13
    jmp .cs_loop
.entry_check:
    ; entry 0 (e.g. a shared object) carries no code address -> skip
    mov rax, [ehdr + E_ENTRY]
    test rax, rax
    jz .sections
    cmp byte [sec_entry_ok], 1
    je .sections
    VP s_entry_pre
    mov rax, [ehdr + E_ENTRY]
    call vhex
    VP s_entry_post
    inc qword [warnings]
.sections:
    ; --- phase 2: section headers ---
    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jnz .have_sections
    VP s_noshdr
    inc qword [warnings]
    jmp .stack
.have_sections:
    call load_shstrtab                 ; for section names (overwrites [shdr])
    xor r13, r13
.sec_loop:
    cmp r13, r14
    jae .stack
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
    jl .stack                         ; short read -> stop scanning
    ; writable + executable section?
    mov rax, [shdr + SH_FLAGS]
    and rax, (SHF_WRITE | SHF_EXECINSTR)
    cmp rax, (SHF_WRITE | SHF_EXECINSTR)
    jne .sec_next
    VP s_wxsect_pre
    call section_name_ptr             ; rsi -> section name
    call vprint
    VP s_wxsect_post
    inc qword [warnings]
    inc qword [sec_wxsect]
.sec_next:
    inc r13
    jmp .sec_loop
.stack:
    cmp byte [sec_stack], 2
    je .stack_exec
    cmp byte [sec_stack], 0
    je .stack_absent
    jmp .summary                      ; state 1 = non-executable stack: fine
.stack_exec:
    VP s_execstack
    inc qword [warnings]
    jmp .summary
.stack_absent:
    VP s_nostack
    inc qword [warnings]
.summary:
    cmp qword [warnings], 0
    jne .some
    VP sec_ok
    ret
.some:
    VP two_spaces
    mov rax, [warnings]
    call vdec
    VP sec_summary
    ret

; ---------------------------------------------------------------------------
; find_section - locate the first section header of a given type.
;   in:  eax = SH_TYPE to find
;   out: rax = section index, or -1 if none; matching header left in [shdr]
;   fd is in r12 (preserved).  rbx/r13/r14 saved for the caller.
; ---------------------------------------------------------------------------
find_section:
    push rbx
    push r13
    push r14
    mov ebx, eax                ; target section type
    movzx r14d, word [ehdr + E_SHNUM]
    xor r13, r13
.fs_loop:
    cmp r13, r14
    jae .fs_notfound
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
    jl .fs_notfound
    mov eax, dword [shdr + SH_TYPE]
    cmp eax, ebx
    je .fs_found
    inc r13
    jmp .fs_loop
.fs_found:
    mov rax, r13
    pop r14
    pop r13
    pop rbx
    ret
.fs_notfound:
    mov rax, -1
    pop r14
    pop r13
    pop rbx
    ret

; ---------------------------------------------------------------------------
; load_dynstr - read a string-table section (by index) into [dynstr];
;   byte count stored in [dynstr_len] (0 on failure).  Overwrites [shdr].
;   in: eax = section index of the string table
; ---------------------------------------------------------------------------
load_dynstr:
    mov qword [dynstr_len], 0
    test eax, eax
    jz .ld_ret                 ; index 0 = no string table
    movzx ecx, word [ehdr + E_SHENTSIZE]
    imul rax, rcx
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
    jl .ld_ret
    mov rdx, [shdr + SH_SIZE]  ; clamp request to DYNSTR_CAP
    cmp rdx, DYNSTR_CAP
    jbe .ld_cap
    mov rdx, DYNSTR_CAP
.ld_cap:
    mov rdi, r12
    mov rsi, [shdr + SH_OFFSET]
    push rdx
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
    pop rdx
    mov rdi, r12
    lea rsi, [dynstr]
    mov rax, SYS_READ
    syscall
    test rax, rax
    js .ld_ret                 ; error -> len stays 0
    mov [dynstr_len], rax
    lea rsi, [dynstr]          ; guarantee NUL termination
    mov byte [rsi + rax], 0
.ld_ret:
    ret

; ---------------------------------------------------------------------------
; dynstr_name_ptr - resolve an offset into the dynamic string table.
;   in:  rax = byte offset
;   out: rsi -> NUL-terminated name (empty_str if out of range)
; ---------------------------------------------------------------------------
dynstr_name_ptr:
    cmp rax, [dynstr_len]
    jae .dn_empty
    lea rsi, [dynstr]
    add rsi, rax
    ret
.dn_empty:
    lea rsi, [empty_str]
    ret

; ---------------------------------------------------------------------------
