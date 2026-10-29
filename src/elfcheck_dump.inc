; ---------------------------------------------------------------------------
; Section dumps: -x/--hex-dump and -p/--string-dump (readelf -x / -p parity).
; All output is assembled into [linebuf] and flushed with a single write, so
; even large sections stay syscall-light.  r12 = open fd throughout.
; ---------------------------------------------------------------------------

; dump_sections - run the requested -x / -p dumps (names in [hexdump_name] /
;   [strdump_name]).  Missing sections warn on stderr and set [dump_error].
dump_sections:
    call load_shstrtab              ; section-name table -> [strtab]
    cmp qword [hexdump_name], 0
    je .ds_str
    mov rsi, [hexdump_name]
    call find_section_by_name       ; rax = index or -1, fills [shdr]
    cmp rax, -1
    je .ds_hex_nf
    mov rsi, [hexdump_name]
    call hex_dump_section
    jmp .ds_str
.ds_hex_nf:
    mov rsi, [hexdump_name]
    call dump_not_found
.ds_str:
    cmp qword [strdump_name], 0
    je .ds_ret
    mov rsi, [strdump_name]
    call find_section_by_name
    cmp rax, -1
    je .ds_str_nf
    mov rsi, [strdump_name]
    call str_dump_section
    jmp .ds_ret
.ds_str_nf:
    mov rsi, [strdump_name]
    call dump_not_found
.ds_ret:
    ret

; find_section_by_name - locate a section by name (needs load_shstrtab first).
;   in:  rsi = NUL-terminated target name
;   out: rax = section index (>=0) with [shdr] filled, or -1 if not found
find_section_by_name:
    push rbx
    push r13
    push r14
    push r15
    mov r15, rsi                    ; target name
    movzx r14d, word [ehdr + E_SHNUM]
    xor r13, r13
.fn_loop:
    cmp r13, r14
    jae .fn_nf
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
    jl .fn_nf
    call section_name_ptr           ; rsi -> this section's name
    mov rdi, r15
    call streq
    test al, al
    jnz .fn_found
    inc r13
    jmp .fn_loop
.fn_found:
    mov rax, r13
    pop r15
    pop r14
    pop r13
    pop rbx
    ret
.fn_nf:
    mov rax, -1
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; hex_dump_section - readelf -x of the section in [shdr].  in: rsi = name
;   r13 = display address, r14 = bytes left, rbx = bytes this row, r10 = buf
hex_dump_section:
    push rbx
    push r13
    push r14
    push r15
    mov r15, rsi                    ; name (header)
    lea rsi, [hexdump_hdr]
    call print_cstr
    mov rsi, r15
    call print_cstr
    lea rsi, [dump_hdr_tail]
    call print_cstr
    mov r13, [shdr + SH_ADDR]
    mov r14, [shdr + SH_SIZE]
    mov rdi, r12                    ; seek to the section data
    mov rsi, [shdr + SH_OFFSET]
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
.hx_row:
    test r14, r14
    jz .hx_done
    mov rdx, 16                     ; n = min(16, remaining)
    cmp r14, 16
    jae .hx_have
    mov rdx, r14
.hx_have:
    mov rdi, r12
    lea rsi, [dump_buf]
    mov rax, SYS_READ
    syscall
    test rax, rax
    jle .hx_done
    mov rbx, rax                    ; bytes available this row
    lea r10, [dump_buf]
    lea rdi, [linebuf]
    mov byte [rdi], ' '
    mov byte [rdi + 1], ' '
    mov byte [rdi + 2], '0'
    mov byte [rdi + 3], 'x'
    add rdi, 4
    mov rax, r13                    ; address, >= 8 hex digits
    call append_hex_min8
    xor rcx, rcx                    ; j = 0..15
.hx_byte:
    cmp rcx, 16
    jae .hx_ascii
    mov rax, rcx                    ; space before each 4-byte group
    and rax, 3
    jnz .hx_nosep
    mov byte [rdi], ' '
    inc rdi
.hx_nosep:
    cmp rcx, rbx
    jae .hx_blank
    movzx edx, byte [r10 + rcx]
    mov r11d, edx
    mov eax, edx
    shr eax, 4
    call hexnib
    mov [rdi], al
    inc rdi
    mov eax, r11d
    call hexnib
    mov [rdi], al
    inc rdi
    jmp .hx_next
.hx_blank:
    mov byte [rdi], ' '
    mov byte [rdi + 1], ' '
    add rdi, 2
.hx_next:
    inc rcx
    jmp .hx_byte
.hx_ascii:
    mov byte [rdi], ' '            ; separator before the ASCII column
    inc rdi
    xor rcx, rcx
.hx_a:
    cmp rcx, rbx
    jae .hx_a_done
    movzx eax, byte [r10 + rcx]
    cmp al, 0x20
    jb .hx_dot
    cmp al, 0x7e
    ja .hx_dot
    jmp .hx_put
.hx_dot:
    mov al, '.'
.hx_put:
    mov [rdi], al
    inc rdi
    inc rcx
    jmp .hx_a
.hx_a_done:
    mov byte [rdi], 10
    inc rdi
    lea rsi, [linebuf]
    mov rdx, rdi
    sub rdx, rsi
    call print_str
    add r13, rbx
    sub r14, rbx
    jmp .hx_row
.hx_done:
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; str_dump_section - readelf -p of the section in [shdr].  in: rsi = name
;   r13 = byte offset, r14 = bytes left, r15 = in-string flag, rbx = write ptr,
;   r9 = chunk length, r10 = chunk index
str_dump_section:
    push rbx
    push r13
    push r14
    push r15
    mov r15, rsi
    lea rsi, [strdump_hdr]
    call print_cstr
    mov rsi, r15
    call print_cstr
    lea rsi, [dump_hdr_tail]
    call print_cstr
    xor r15, r15                    ; in_string = 0
    xor r13, r13                    ; offset = 0
    mov r14, [shdr + SH_SIZE]
    mov rdi, r12
    mov rsi, [shdr + SH_OFFSET]
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
.sd_chunk:
    test r14, r14
    jz .sd_end
    mov rdx, DUMP_CHUNK
    cmp r14, rdx
    jae .sd_have
    mov rdx, r14
.sd_have:
    mov rdi, r12
    lea rsi, [dump_buf]
    mov rax, SYS_READ
    syscall
    test rax, rax
    jle .sd_end
    mov r9, rax
    sub r14, r9
    xor r10, r10
.sd_byte:
    cmp r10, r9
    jae .sd_chunk
    lea rax, [dump_buf]
    movzx edx, byte [rax + r10]
    cmp dl, 0x20
    jb .sd_np
    cmp dl, 0x7e
    ja .sd_np
    cmp r15, 0                      ; printable byte
    jne .sd_app
    lea rbx, [linebuf]             ; start a new string: "  [<hex6>]  "
    mov byte [rbx], ' '
    mov byte [rbx + 1], ' '
    mov byte [rbx + 2], '['
    add rbx, 3
    mov rax, r13
    mov rdi, rbx
    call append_hex6
    mov rbx, rdi
    mov byte [rbx], ']'
    mov byte [rbx + 1], ' '
    mov byte [rbx + 2], ' '
    add rbx, 3
    mov r15, 1
.sd_app:
    lea rax, [dump_buf]            ; reload: append_hex6 clobbered rdx
    movzx edx, byte [rax + r10]
    mov [rbx], dl
    inc rbx
    lea rax, [linebuf + LINEBUF_FLUSH]
    cmp rbx, rax
    jb .sd_adv
    lea rsi, [linebuf]            ; flush a long run without a newline
    mov rdx, rbx
    sub rdx, rsi
    call print_str
    lea rbx, [linebuf]
.sd_adv:
    inc r13
    inc r10
    jmp .sd_byte
.sd_np:
    cmp r15, 0
    je .sd_adv2
    mov byte [rbx], 10
    inc rbx
    lea rsi, [linebuf]
    mov rdx, rbx
    sub rdx, rsi
    call print_str
    xor r15, r15
.sd_adv2:
    inc r13
    inc r10
    jmp .sd_byte
.sd_end:
    cmp r15, 0
    je .sd_ret
    mov byte [rbx], 10
    inc rbx
    lea rsi, [linebuf]
    mov rdx, rbx
    sub rdx, rsi
    call print_str
.sd_ret:
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; dump_not_found - warn on stderr and flag the error.  in: rsi = section name
dump_not_found:
    mov byte [dump_error], 1
    push rsi
    lea rsi, [dump_nf1]
    call print_cstr_err
    pop rsi
    call print_cstr_err
    lea rsi, [dump_nf2]
    call print_cstr_err
    ret

; print_cstr_err - write a NUL-terminated string (rsi) to stderr
print_cstr_err:
    xor rdx, rdx
.pce_len:
    cmp byte [rsi + rdx], 0
    je .pce_out
    inc rdx
    jmp .pce_len
.pce_out:
    call print_stderr
    ret

; hexnib - low nibble of al -> ASCII hex digit in al (touches only al)
hexnib:
    and al, 0xf
    cmp al, 10
    jb .hn_dig
    add al, 'a' - 10
    ret
.hn_dig:
    add al, '0'
    ret

; append_hex_min8 - append rax as lowercase hex, >= 8 digits, to [rdi]
;   out: rdi advanced.  Clobbers rax, rcx, rdx, r8.
append_hex_min8:
    mov r8, rax
    mov rcx, 60
.a8_find:
    cmp rcx, 28
    jbe .a8_emit
    mov rdx, r8
    shr rdx, cl
    and rdx, 0xf
    jnz .a8_emit
    sub rcx, 4
    jmp .a8_find
.a8_emit:
    mov rdx, r8
    shr rdx, cl
    and rdx, 0xf
    mov al, dl
    call hexnib
    mov [rdi], al
    inc rdi
    sub rcx, 4
    jns .a8_emit
    ret

; append_hex6 - append rax as lowercase hex, right-justified in a width-6
;   space-padded field, to [rdi].  out: rdi advanced.
append_hex6:
    push r14
    push r15
    mov r15, rdi                    ; destination
    call fmt_hex                    ; rsi -> "0x" + digits (preserves r12/rbx)
    add rsi, 2                      ; skip the "0x" prefix
    xor rdx, rdx
.a6_len:
    cmp byte [rsi + rdx], 0
    je .a6_pad
    inc rdx
    jmp .a6_len
.a6_pad:
    mov r14, rsi                    ; digits
    mov rcx, 6
    sub rcx, rdx
    jle .a6_copy
.a6_sp:
    mov byte [r15], ' '
    inc r15
    dec rcx
    jnz .a6_sp
.a6_copy:
    xor rcx, rcx
.a6_cp:
    cmp rcx, rdx
    jae .a6_fin
    mov al, [r14 + rcx]
    mov [r15], al
    inc r15
    inc rcx
    jmp .a6_cp
.a6_fin:
    mov rdi, r15
    pop r15
    pop r14
    ret
