; print_needed - list DT_NEEDED entries from the .dynamic section.
;   uses [dyn_off]/[dyn_size]; dynstr must already be loaded.
; ---------------------------------------------------------------------------
print_needed:
    PRINT dyn_needed_hdr
    mov r14, [dyn_size]
    shr r14, 4                 ; count = size / 16
    xor r13, r13
    xor rbx, rbx               ; number of DT_NEEDED printed
.pn_loop:
    cmp r13, r14
    jae .pn_done
    mov rax, r13
    shl rax, 4                 ; index * 16
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
    jl .pn_done
    mov rax, [dynent]          ; d_tag
    test rax, rax
    jz .pn_done                ; DT_NULL terminates the array
    cmp rax, 1                 ; DT_NEEDED
    jne .pn_next
    mov rax, [dynent + 8]      ; d_val = string-table offset
    call dynstr_name_ptr
    push rsi
    PRINT dyn_indent
    pop rsi
    call print_cstr
    PRINT nl
    inc rbx
.pn_next:
    inc r13
    jmp .pn_loop
.pn_done:
    test rbx, rbx
    jnz .pn_ret
    PRINT dyn_none
.pn_ret:
    ret

; ---------------------------------------------------------------------------
; print_imports - list undefined (imported) symbols from .dynsym.
;   uses [dsym_off]/[dsym_size]/[dsym_ent]; dynstr must already be loaded.
; ---------------------------------------------------------------------------
print_imports:
    PRINT dyn_imports_hdr
    mov rcx, [dsym_ent]
    test rcx, rcx
    jz .pi_none                ; no entry size -> nothing to iterate
    mov rax, [dsym_size]
    xor rdx, rdx
    div rcx                    ; rax = count = size / entsize
    mov r14, rax
    xor r13, r13
    xor rbx, rbx               ; number of imports printed
.pi_loop:
    cmp r13, r14
    jae .pi_done
    mov rax, r13
    mul qword [dsym_ent]       ; index * entsize (result in rax)
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
    jl .pi_done
    movzx eax, word [syment + 6]  ; st_shndx
    test eax, eax
    jnz .pi_next               ; defined here -> not an import
    mov eax, dword [syment]       ; st_name
    test eax, eax
    jz .pi_next                ; no name -> skip
    call dynstr_name_ptr
    push rsi
    PRINT dyn_indent
    pop rsi
    call print_cstr
    mov rdi, [dsym_index]
    mov rsi, r13
    call print_symbol_version_suffix
    PRINT nl
    inc rbx
.pi_next:
    inc r13
    jmp .pi_loop
.pi_done:
    test rbx, rbx
    jnz .pi_ret
.pi_none:
    PRINT dyn_none
.pi_ret:
    ret

; ---------------------------------------------------------------------------
; analyze_dynamic - print the "Dynamic:" section: needed libraries and
;   imported symbols, or a note when the binary is statically linked.
; ---------------------------------------------------------------------------
analyze_dynamic:
    PRINT dyn_title
    mov byte [dyn_is_static], 0
    cmp word [ehdr + E_SHNUM], 0
    jne .ad_haveshn
    PRINT dyn_nosh
    ret
.ad_haveshn:
    mov eax, 6                 ; SHT_DYNAMIC
    call find_section
    cmp rax, -1
    jne .ad_dynamic
    mov byte [dyn_is_static], 1
    PRINT dyn_static
    ret
.ad_dynamic:
    ; snapshot .dynamic location before load_dynstr overwrites [shdr]
    mov rax, [shdr + SH_OFFSET]
    mov [dyn_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [dyn_size], rax
    mov eax, dword [shdr + SH_LINK]
    mov [dyn_link], eax
    mov eax, dword [dyn_link]  ; load .dynstr (via .dynamic sh_link)
    call load_dynstr
    call print_needed
    mov eax, 11                ; SHT_DYNSYM
    call find_section
    cmp rax, -1
    je .ad_ret
    mov [dsym_index], eax
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
    call prepare_symbol_versions
    mov eax, dword [dsym_link]
    call load_dynstr
    call print_imports
.ad_ret:
    ret

; ---------------------------------------------------------------------------
