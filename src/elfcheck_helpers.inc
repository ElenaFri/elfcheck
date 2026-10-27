; ends_chk - test whether the NUL-terminated string in rsi ends with "_chk".
;   out: al = 1 if it does, else 0.  rsi preserved.
ends_chk:
    xor rcx, rcx
.ec_len:
    cmp byte [rsi + rcx], 0
    je .ec_have
    inc rcx
    jmp .ec_len
.ec_have:
    cmp rcx, 4
    jb .ec_no
    lea rdx, [rsi + rcx - 4]
    cmp byte [rdx], '_'
    jne .ec_no
    cmp byte [rdx + 1], 'c'
    jne .ec_no
    cmp byte [rdx + 2], 'h'
    jne .ec_no
    cmp byte [rdx + 3], 'k'
    jne .ec_no
    mov al, 1
    ret
.ec_no:
    xor al, al
    ret

; ---------------------------------------------------------------------------
; streq - compare two NUL-terminated strings.
;   in:  rsi, rdi = string pointers
;   out: al = 1 if equal, else 0.  rsi/rdi preserved.
; ---------------------------------------------------------------------------
streq:
    push rsi
    push rdi
.se_loop:
    mov al, [rsi]
    mov dl, [rdi]
    cmp al, dl
    jne .se_ne
    test al, al
    jz .se_eq
    inc rsi
    inc rdi
    jmp .se_loop
.se_eq:
    mov al, 1
    jmp .se_out
.se_ne:
    xor al, al
.se_out:
    pop rdi
    pop rsi
    ret

; ---------------------------------------------------------------------------
; vprint / vdec / vhex - like print_cstr/print_dec/print_hex, but no-ops when
; [silent] is set.  Lets validate_structure double as a silent issue counter.
; ---------------------------------------------------------------------------
vprint:                    ; in: rsi = cstr
    cmp byte [silent], 0
    jne .v_skip
    call print_cstr
.v_skip:
    ret

vdec:                      ; in: rax = value
    cmp byte [silent], 0
    jne .vd_skip
    call print_dec
.vd_skip:
    ret

vhex:                      ; in: rax = value
    cmp byte [silent], 0
    jne .vh_skip
    call print_hex
.vh_skip:
    ret

; ---------------------------------------------------------------------------
