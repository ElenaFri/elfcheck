; check_hardening - report exploit-mitigation posture (checksec-style):
;   RELRO, stack canary, NX, PIE, CET, RPATH/RUNPATH and Fortify.
;   Gathers facts into hd_* then prints them.  Uses VP/vprint/vdec so it also
;   populates the hd_* fields silently for the JSON path.  fd in r12.
; ---------------------------------------------------------------------------
check_hardening:
    VP hd_title
    call hd_scan_phdrs         ; -> hd_interp, hd_stack, hd_relro_seg
    call hd_scan_gnu_properties ; -> hd_cet_seen / hd_cet_flags
    call hd_scan_dynamic       ; -> hd_bindnow, hd_flags1, hd_rpath/runpath_off
    call hd_scan_imports       ; -> hd_canary, hd_fortify (loads .dynstr last)
    ; --- RELRO ---
    VP hd_relro_lbl
    cmp byte [hd_relro_seg], 0
    je .h_relro_none
    cmp byte [hd_bindnow], 0
    jne .h_relro_full
    VP hd_partial
    jmp .h_canary
.h_relro_full:
    VP hd_full
    jmp .h_canary
.h_relro_none:
    VP hd_none
.h_canary:
    ; --- Stack canary ---
    VP hd_canary_lbl
    cmp byte [hd_canary], 0
    jne .h_canary_yes
    VP hd_no
    jmp .h_nx
.h_canary_yes:
    VP hd_yes
.h_nx:
    ; --- NX (non-executable stack) ---
    VP hd_nx_lbl
    cmp byte [hd_stack], 2
    je .h_nx_dis
    cmp byte [hd_stack], 0
    je .h_nx_unknown
    VP hd_enabled
    jmp .h_pie
.h_nx_dis:
    VP hd_disabled
    jmp .h_pie
.h_nx_unknown:
    VP hd_unknown
.h_pie:
    ; --- PIE ---
    VP hd_pie_lbl
    movzx eax, word [ehdr + E_TYPE]
    cmp eax, ET_EXEC
    je .h_pie_no
    cmp eax, ET_DYN
    jne .h_pie_na
    cmp byte [hd_interp], 0
    je .h_pie_dso
    VP hd_enabled
    jmp .h_ibt
.h_pie_no:
    VP hd_disabled
    jmp .h_ibt
.h_pie_dso:
    VP hd_dso
    jmp .h_ibt
.h_pie_na:
    VP hd_na
.h_ibt:
    VP hd_ibt_lbl
    mov ecx, GNU_PROPERTY_X86_FEATURE_1_IBT
    call hd_print_cet_status
.h_shstk:
    VP hd_shstk_lbl
    mov ecx, GNU_PROPERTY_X86_FEATURE_1_SHSTK
    call hd_print_cet_status
.h_rpath:
    ; --- RPATH ---
    VP hd_rpath_lbl
    cmp qword [hd_rpath_off], -1
    je .h_rpath_none
    mov rax, [hd_rpath_off]
    call dynstr_name_ptr
    call vprint
    VP nl
    jmp .h_runpath
.h_rpath_none:
    VP hd_notset
.h_runpath:
    ; --- RUNPATH ---
    VP hd_runpath_lbl
    cmp qword [hd_runpath_off], -1
    je .h_runpath_none
    mov rax, [hd_runpath_off]
    call dynstr_name_ptr
    call vprint
    VP nl
    jmp .h_fortify
.h_runpath_none:
    VP hd_notset
.h_fortify:
    ; --- Fortify ---
    VP hd_fortify_lbl
    cmp qword [hd_fortify], 0
    je .h_fortify_no
    mov rax, [hd_fortify]
    call vdec
    VP hd_fortify_fns
    ret
.h_fortify_no:
    VP hd_no
    ret

; hd_scan_phdrs - set hd_interp / hd_stack / hd_relro_seg from program headers
hd_scan_phdrs:
    mov byte [hd_interp], 0
    mov byte [hd_stack], 0
    mov byte [hd_relro_seg], 0
    movzx r14d, word [ehdr + E_PHNUM]
    test r14, r14
    jz .sp_done
    xor r13, r13
.sp_loop:
    cmp r13, r14
    jae .sp_done
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
    jl .sp_done
    mov eax, dword [phdr + P_TYPE]
    cmp eax, PT_INTERP
    jne .sp_c1
    mov byte [hd_interp], 1
    jmp .sp_next
.sp_c1:
    cmp eax, PT_GNU_STACK
    jne .sp_c2
    mov byte [hd_stack], 1
    test byte [phdr + P_FLAGS], PF_X
    jz .sp_next
    mov byte [hd_stack], 2
    jmp .sp_next
.sp_c2:
    cmp eax, PT_GNU_RELRO
    jne .sp_next
    mov byte [hd_relro_seg], 1
.sp_next:
    inc r13
    jmp .sp_loop
.sp_done:
    ret

; Scan PT_NOTE/PT_GNU_PROPERTY and SHT_NOTE ranges for GNU x86 feature properties.
hd_scan_gnu_properties:
    push r13
    push r14
    push r15
    mov byte [hd_cet_seen], 0
    mov dword [hd_cet_flags], 0

    mov rdi, r12
    xor esi, esi
    mov edx, SEEK_END
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .hgp_done
    mov [filesize], rax

    movzx r14d, word [ehdr + E_PHNUM]
    test r14, r14
    jz .hgp_sections
    movzx r15d, word [ehdr + E_PHENTSIZE]
    cmp r15d, PHDR_SIZE
    jb .hgp_sections
    mov rax, r14
    mov rcx, r15
    mul rcx
    test rdx, rdx
    jnz .hgp_sections
    add rax, [ehdr + E_PHOFF]
    jc .hgp_sections
    cmp rax, [filesize]
    ja .hgp_sections
    xor r13, r13
.hgp_phdr_loop:
    cmp r13, r14
    jae .hgp_sections
    mov rax, r13
    imul rax, r15
    add rax, [ehdr + E_PHOFF]
    jc .hgp_sections
    lea rsi, [phdr]
    mov edx, PHDR_SIZE
    call read_note_at
    cmp eax, 1
    jne .hgp_sections
    mov eax, dword [phdr + P_TYPE]
    cmp eax, PT_NOTE
    je .hgp_phdr_note
    cmp eax, PT_GNU_PROPERTY
    jne .hgp_phdr_next
.hgp_phdr_note:
    mov rax, [phdr + P_OFFSET]
    mov [note_range_off], rax
    mov rax, [phdr + P_FILESZ]
    mov [note_range_size], rax
    call scan_gnu_note_range
.hgp_phdr_next:
    inc r13
    jmp .hgp_phdr_loop

.hgp_sections:
    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .hgp_done
    movzx r15d, word [ehdr + E_SHENTSIZE]
    cmp r15d, SHDR_SIZE
    jb .hgp_done
    mov rax, r14
    mov rcx, r15
    mul rcx
    test rdx, rdx
    jnz .hgp_done
    add rax, [ehdr + E_SHOFF]
    jc .hgp_done
    cmp rax, [filesize]
    ja .hgp_done
    xor r13, r13
.hgp_shdr_loop:
    cmp r13, r14
    jae .hgp_done
    mov rax, r13
    imul rax, r15
    add rax, [ehdr + E_SHOFF]
    jc .hgp_done
    lea rsi, [shdr]
    mov edx, SHDR_SIZE
    call read_note_at
    cmp eax, 1
    jne .hgp_done
    cmp dword [shdr + SH_TYPE], SHT_NOTE
    jne .hgp_shdr_next
    mov rax, [shdr + SH_OFFSET]
    mov [note_range_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [note_range_size], rax
    call scan_gnu_note_range
.hgp_shdr_next:
    inc r13
    jmp .hgp_shdr_loop
.hgp_done:
    pop r15
    pop r14
    pop r13
    ret

; Check [note_rel, note_rel + note_len) against the current note range and file.
note_range_ok:
    mov rax, [note_rel]
    add rax, [note_len]
    jc .nro_no
    cmp rax, [note_range_size]
    ja .nro_no
    mov rdx, [note_range_off]
    add rdx, [note_rel]
    jc .nro_no
    add rdx, [note_len]
    jc .nro_no
    cmp rdx, [filesize]
    ja .nro_no
    mov eax, 1
    ret
.nro_no:
    xor eax, eax
    ret

; Read note-relative bytes after checking both range and file bounds.
read_note_relative:
    mov [note_read_buf], rsi
    mov [note_read_size], rdx
    call note_range_ok
    test eax, eax
    jz .rnr_no
    mov rax, [note_range_off]
    add rax, [note_rel]
    jc .rnr_no
    mov rsi, [note_read_buf]
    mov rdx, [note_read_size]
    call read_note_at
    ret
.rnr_no:
    xor eax, eax
    ret

; Read rdx bytes at absolute offset rax into rsi; returns eax=1 on exact read.
read_note_at:
    mov [note_read_buf], rsi
    mov [note_read_size], rdx
    mov rdi, r12
    mov rsi, rax
    xor edx, edx
    mov eax, SYS_LSEEK
    syscall
    test rax, rax
    js .rna_no
    mov rdi, r12
    mov rsi, [note_read_buf]
    mov rdx, [note_read_size]
    xor eax, eax
    syscall
    cmp rax, [note_read_size]
    jne .rna_no
    mov eax, 1
    ret
.rna_no:
    xor eax, eax
    ret

; Parse aligned Elf_Nhdr records in [note_range_off, note_range_size).
scan_gnu_note_range:
    mov qword [note_cursor], 0
.sgnr_loop:
    mov rax, [note_cursor]
    cmp rax, [note_range_size]
    jae .sgnr_done
    mov [note_rel], rax
    mov qword [note_len], 12
    call note_range_ok
    test eax, eax
    jz .sgnr_done
    lea rsi, [note_header]
    mov edx, 12
    call read_note_relative
    cmp eax, 1
    jne .sgnr_done
    mov eax, dword [note_header]
    mov [note_namesz], eax
    mov eax, dword [note_header + 4]
    mov [note_desc_size], rax
    mov eax, dword [note_header + 8]
    mov [note_type], eax

    mov eax, [note_namesz]
    add eax, 3
    jc .sgnr_done
    and eax, 0xfffffffc
    mov [note_name_pad], rax
    mov rax, [note_cursor]
    add rax, 12
    jc .sgnr_done
    add rax, [note_name_pad]
    jc .sgnr_done
    mov [note_desc_rel], rax
    mov rax, [note_desc_size]
    add rax, 3
    jc .sgnr_done
    and rax, -4
    mov [note_desc_pad], rax
    mov rax, [note_desc_rel]
    add rax, [note_desc_pad]
    jc .sgnr_done
    mov [note_record_end], rax
    mov rax, [note_cursor]
    mov [note_rel], rax
    mov rax, [note_record_end]
    sub rax, [note_cursor]
    mov [note_len], rax
    call note_range_ok
    test eax, eax
    jz .sgnr_done

    cmp dword [note_namesz], 4
    jne .sgnr_next
    cmp dword [note_type], NT_GNU_PROPERTY_TYPE_0
    jne .sgnr_next
    mov rax, [note_cursor]
    add rax, 12
    jc .sgnr_next
    mov [note_rel], rax
    mov qword [note_len], 4
    lea rsi, [note_name]
    mov edx, 4
    call read_note_relative
    cmp eax, 1
    jne .sgnr_next
    cmp dword [note_name], 0x00554e47 ; "GNU\0"
    jne .sgnr_next
    call scan_gnu_property_desc
.sgnr_next:
    mov rax, [note_record_end]
    cmp rax, [note_cursor]
    jbe .sgnr_done
    mov [note_cursor], rax
    jmp .sgnr_loop
.sgnr_done:
    ret

; Parse 8-byte-aligned GNU property entries in the current note description.
scan_gnu_property_desc:
    mov qword [note_prop_cursor], 0
.sgpd_loop:
    mov rax, [note_prop_cursor]
    cmp rax, [note_desc_size]
    jae .sgpd_done
    mov rdx, [note_desc_size]
    sub rdx, rax
    cmp rdx, 8
    jb .sgpd_done
    add rax, [note_desc_rel]
    jc .sgpd_done
    mov [note_rel], rax
    mov qword [note_len], 8
    lea rsi, [note_prop_header]
    mov edx, 8
    call read_note_relative
    cmp eax, 1
    jne .sgpd_done
    mov eax, dword [note_prop_header]
    mov [note_prop_type], eax
    mov eax, dword [note_prop_header + 4]
    mov [note_prop_size], rax

    mov rax, [note_prop_size]
    add rax, 7
    jc .sgpd_done
    and rax, -8
    mov [note_prop_pad], rax
    mov rax, [note_prop_cursor]
    add rax, 8
    jc .sgpd_done
    add rax, [note_prop_pad]
    jc .sgpd_done
    cmp rax, [note_desc_size]
    ja .sgpd_done

    cmp dword [note_prop_type], GNU_PROPERTY_X86_FEATURE_1_AND
    jne .sgpd_next
    cmp qword [note_prop_size], 4
    jne .sgpd_next
    mov rax, [note_desc_rel]
    add rax, [note_prop_cursor]
    jc .sgpd_next
    add rax, 8
    jc .sgpd_next
    mov [note_rel], rax
    mov qword [note_len], 4
    lea rsi, [note_prop_value]
    mov edx, 4
    call read_note_relative
    cmp eax, 1
    jne .sgpd_next
    mov eax, dword [note_prop_value]
    cmp byte [hd_cet_seen], 0
    jne .sgpd_intersect
    mov byte [hd_cet_seen], 1
    mov [hd_cet_flags], eax
    jmp .sgpd_next
.sgpd_intersect:
    and [hd_cet_flags], eax
.sgpd_next:
    mov rax, [note_prop_cursor]
    add rax, 8
    jc .sgpd_done
    add rax, [note_prop_pad]
    jc .sgpd_done
    mov [note_prop_cursor], rax
    jmp .sgpd_loop
.sgpd_done:
    ret

hd_print_cet_status:
    cmp byte [hd_cet_seen], 0
    je .hpcs_unknown
    test dword [hd_cet_flags], ecx
    jz .hpcs_disabled
    VP hd_enabled
    ret
.hpcs_disabled:
    VP hd_disabled
    ret
.hpcs_unknown:
    VP hd_unknown_cet
    ret

; hd_scan_dynamic - read DT_RPATH/RUNPATH/BIND_NOW/FLAGS(_1) from .dynamic
hd_scan_dynamic:
    mov byte [hd_bindnow], 0
    mov qword [hd_flags1], 0
    mov qword [hd_rpath_off], -1
    mov qword [hd_runpath_off], -1
    mov eax, 6                 ; SHT_DYNAMIC
    call find_section
    cmp rax, -1
    je .sd_done
    mov rax, [shdr + SH_OFFSET]
    mov [dyn_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [dyn_size], rax
    mov eax, dword [shdr + SH_LINK]
    mov [dyn_link], eax
    mov eax, dword [dyn_link]
    call load_dynstr
    mov r14, [dyn_size]
    shr r14, 4
    xor r13, r13
.sd_loop:
    cmp r13, r14
    jae .sd_done
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
    jl .sd_done
    mov rax, [dynent]          ; d_tag
    test rax, rax
    jz .sd_done                ; DT_NULL
    cmp rax, DT_RPATH
    jne .sd_t1
    mov rax, [dynent + 8]
    mov [hd_rpath_off], rax
    jmp .sd_next
.sd_t1:
    cmp rax, DT_RUNPATH
    jne .sd_t2
    mov rax, [dynent + 8]
    mov [hd_runpath_off], rax
    jmp .sd_next
.sd_t2:
    cmp rax, DT_BIND_NOW
    jne .sd_t3
    mov byte [hd_bindnow], 1
    jmp .sd_next
.sd_t3:
    cmp rax, DT_FLAGS
    jne .sd_t4
    mov rax, [dynent + 8]
    test rax, DF_BIND_NOW
    jz .sd_next
    mov byte [hd_bindnow], 1
    jmp .sd_next
.sd_t4:
    cmp rax, DT_FLAGS_1
    jne .sd_next
    mov rax, [dynent + 8]
    mov [hd_flags1], rax
    test rax, DF_1_NOW
    jz .sd_next
    mov byte [hd_bindnow], 1
.sd_next:
    inc r13
    jmp .sd_loop
.sd_done:
    ret

; hd_scan_imports - set hd_canary / hd_fortify from the .dynsym imports
hd_scan_imports:
    mov byte [hd_canary], 0
    mov qword [hd_fortify], 0
    mov eax, 11                ; SHT_DYNSYM
    call find_section
    cmp rax, -1
    je .si_done
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
    mov rcx, [dsym_ent]
    test rcx, rcx
    jz .si_done
    mov rax, [dsym_size]
    xor rdx, rdx
    div rcx
    mov r14, rax
    xor r13, r13
.si_loop:
    cmp r13, r14
    jae .si_done
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
    jl .si_done
    movzx eax, word [syment + 6]  ; st_shndx
    test eax, eax
    jnz .si_next               ; defined here -> not an import
    mov eax, dword [syment]       ; st_name
    test eax, eax
    jz .si_next
    call dynstr_name_ptr          ; rsi -> name
    lea rdi, [name_stackchk]
    call streq                    ; rsi/rdi preserved
    test al, al
    jz .si_chk
    mov byte [hd_canary], 1
.si_chk:
    call ends_chk                 ; al=1 if name ends with "_chk"
    test al, al
    jz .si_next
    inc qword [hd_fortify]
.si_next:
    inc r13
    jmp .si_loop
.si_done:
    ret

