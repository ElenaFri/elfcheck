; Enum -> name lookups.  in: eax = value   out: rax = pointer to NUL string
; ---------------------------------------------------------------------------
class_name:
    cmp eax, 1
    je .c32
    cmp eax, 2
    je .c64
    lea rax, [s_class_inv]
    ret
.c32:
    lea rax, [s_class32]
    ret
.c64:
    lea rax, [s_class64]
    ret

data_name:
    cmp eax, 1
    je .le
    cmp eax, 2
    je .be
    lea rax, [s_data_inv]
    ret
.le:
    lea rax, [s_data_le]
    ret
.be:
    lea rax, [s_data_be]
    ret

osabi_name:
    cmp eax, 0
    je .sysv
    cmp eax, 3
    je .linux
    lea rax, [s_osabi_other]
    ret
.sysv:
    lea rax, [s_osabi_sysv]
    ret
.linux:
    lea rax, [s_osabi_linux]
    ret

type_name:
    cmp eax, 0
    je .none
    cmp eax, 1
    je .rel
    cmp eax, 2
    je .exec
    cmp eax, 3
    je .dyn
    cmp eax, 4
    je .core
    lea rax, [s_type_unknown]
    ret
.none:
    lea rax, [s_type_none]
    ret
.rel:
    lea rax, [s_type_rel]
    ret
.exec:
    lea rax, [s_type_exec]
    ret
.dyn:
    lea rax, [s_type_dyn]
    ret
.core:
    lea rax, [s_type_core]
    ret

machine_name:
    cmp eax, 3
    je .i386
    cmp eax, 62
    je .x8664
    cmp eax, 40
    je .arm
    cmp eax, 183
    je .aarch64
    cmp eax, 243
    je .riscv
    lea rax, [s_mach_unknown]
    ret
.i386:
    lea rax, [s_mach_386]
    ret
.x8664:
    lea rax, [s_mach_x8664]
    ret
.arm:
    lea rax, [s_mach_arm]
    ret
.aarch64:
    lea rax, [s_mach_aarch64]
    ret
.riscv:
    lea rax, [s_mach_riscv]
    ret

; ---------------------------------------------------------------------------
; fmt_hex - format "0x" + minimal-width hex of rax into numbuf (NUL-terminated)
;           out: rsi = pointer to the string
; ---------------------------------------------------------------------------
fmt_hex:                   ; in: rax = value
    push rbx
    push r12
    mov r12, rax           ; value
    lea rbx, [numbuf]      ; write pointer
    mov byte [rbx], '0'
    mov byte [rbx + 1], 'x'
    add rbx, 2
    mov rcx, 60            ; start at most-significant nibble
.skip:
    cmp rcx, 0
    je .emit
    mov rax, r12
    shr rax, cl
    and rax, 0xf
    jnz .emit
    sub rcx, 4
    jmp .skip
.emit:
    mov rax, r12
    shr rax, cl
    and rax, 0xf
    cmp al, 10
    jb .digit
    add al, 'a' - 10
    jmp .store
.digit:
    add al, '0'
.store:
    mov [rbx], al
    inc rbx
    sub rcx, 4
    jns .emit
    mov byte [rbx], 0      ; NUL terminate
    lea rsi, [numbuf]
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; fmt_dec - format unsigned decimal of rax into numbuf (NUL-terminated)
;           out: rsi = pointer to the first digit
; ---------------------------------------------------------------------------
fmt_dec:                   ; in: rax = value
    push rbx
    mov rcx, 10
    mov byte [numbuf + 31], 0   ; NUL
    lea rbx, [numbuf + 30]      ; build digits backward
    test rax, rax
    jnz .loop
    mov byte [rbx], '0'
    dec rbx
    jmp .done
.loop:
    test rax, rax
    jz .done
    xor rdx, rdx
    div rcx                ; rdx:rax / 10 -> rax quot, rdx rem
    add dl, '0'
    mov [rbx], dl
    dec rbx
    jmp .loop
.done:
    inc rbx
    mov rsi, rbx
    pop rbx
    ret

; ---------------------------------------------------------------------------
; print_hex / print_dec - format and print rax to stdout
; ---------------------------------------------------------------------------
print_hex:                 ; in: rax = value
    call fmt_hex
    call print_cstr
    ret

print_dec:                 ; in: rax = value
    call fmt_dec
    call print_cstr
    ret

; ---------------------------------------------------------------------------
; pfield_hex / pfield_dec - format rax, then print left-justified in a field
;                           of width ecx (space-padded)
; ---------------------------------------------------------------------------
pfield_hex:                ; in: rax = value, ecx = width
    push rcx
    call fmt_hex           ; rsi -> string
    pop rcx
    call print_cstr_pad
    ret

pfield_dec:                ; in: rax = value, ecx = width
    push rcx
    call fmt_dec           ; rsi -> string
    pop rcx
    call print_cstr_pad
    ret

; ---------------------------------------------------------------------------
; print_cstr - print NUL-terminated string (rsi) to stdout
; ---------------------------------------------------------------------------
print_cstr:                ; in: rsi = pointer
    xor rdx, rdx
.len:
    cmp byte [rsi + rdx], 0
    je .out
    inc rdx
    jmp .len
.out:
    call print_str
    ret

; ---------------------------------------------------------------------------
; print_cstr_pad - print NUL-terminated string (rsi) then pad with spaces to
; a fixed field width.  in: rsi = pointer, ecx = width (<= 16)
; Does not clobber r12/r13/r14.
; ---------------------------------------------------------------------------
print_cstr_pad:            ; in: rsi = pointer, ecx = width
    push rbx
    mov ebx, ecx           ; save width
    xor rdx, rdx           ; strlen -> rdx
.pcp_len:
    cmp byte [rsi + rdx], 0
    je .pcp_print
    inc rdx
    jmp .pcp_len
.pcp_print:
    push rdx               ; save len
    call print_str         ; print rsi, rdx
    pop rdx
    mov ecx, ebx           ; pad = width - len
    sub ecx, edx
    jle .pcp_done
    lea rsi, [spaces]
    movzx rdx, cx
    call print_str
.pcp_done:
    pop rbx
    ret

; ---------------------------------------------------------------------------
; print_hex_err - format and print rax to stderr
print_str:                 ; in: rsi = buf, rdx = len  -> stdout
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    syscall
    ret

print_stderr:              ; in: rsi = buf, rdx = len  -> stderr
    mov rax, SYS_WRITE
    mov rdi, STDERR
    syscall
    ret

; ---------------------------------------------------------------------------
; print_hex_err - format and print rax to stderr
; ---------------------------------------------------------------------------
print_hex_err:                 ; in: rax = value
    call fmt_hex
    call print_cstr_err
    ret

; ---------------------------------------------------------------------------
; pfield_dec2 - format rax as 2-digit decimal (leading zero), then print left-
;               justified in a field of width ecx (space-padded)
; ---------------------------------------------------------------------------
pfield_dec2:                ; in: rax = value, ecx = width
    push rcx
    push rax
    push rbx
    push rdx
    mov byte [numbuf + 31], 0   ; NUL
    lea rbx, [numbuf + 30]      ; build digits backward
    mov rax, rax                ; value
    mov rcx, 10
    xor rdx, rdx
    div rcx
    add dl, '0'
    mov [rbx], dl
    dec rbx
    xor rdx, rdx
    div rcx
    add dl, '0'
    mov [rbx], dl
    lea rsi, [rbx]
    pop rdx
    pop rbx
    pop rax
    pop rcx
    call print_cstr_pad
    ret
