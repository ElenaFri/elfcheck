; ===========================================================================
; Entropy / packer detection (--entropy)
;
; Computes the Shannon entropy (bits per byte, 0..8) of each section's file
; content by streaming it through a 256-bin byte histogram.  High entropy in an
; executable section is a classic sign of packed / encrypted / compressed code,
; something readelf cannot tell you.  The report is available on its own
; (--entropy), inside --json, and as a triage finding.
;
;   H = log2(N) - (1/N) * sum_i( count_i * log2(count_i) )
;
; log2 is evaluated in Q16 fixed point via bsr + a 256-entry mantissa table
; (log2_frac), which is accurate to a few thousandths of a bit.
; ===========================================================================

; log2_fp - fixed-point base-2 logarithm.
;   in:  rax = x (must be >= 1)
;   out: rax = log2(x) in Q16 (value << 16)
;   clobbers rcx, rdx, r8, r9
log2_fp:
    bsr rdx, rax               ; rdx = index of the most significant set bit
    mov r8, rax                ; working copy of x
    cmp rdx, 8
    jb .lf_small
    mov rcx, rdx
    sub rcx, 8                 ; keep the leading 1 plus 8 mantissa bits
    shr r8, cl
    jmp .lf_mask
.lf_small:
    mov rcx, 8
    sub rcx, rdx
    shl r8, cl
.lf_mask:
    and r8d, 0xFF              ; mantissa index (leading 1 sits at bit 8, dropped)
    mov rax, rdx
    shl rax, 16               ; integer part (msb) in Q16
    lea r9, [log2_frac]
    mov r9d, [r9 + r8*4]      ; fractional part (Q16)
    add rax, r9
    ret

; section_entropy - Shannon entropy of the section described by [shdr].
;   in:  [shdr] filled (uses SH_OFFSET / SH_SIZE); fd in r12.
;   out: rax = entropy in thousandths of a bit/byte (0..8000); 0 if no data.
;   Streams the bytes in DUMP_CHUNK blocks, so memory use is bounded.
section_entropy:
    push rbx
    push r13
    push r14
    push r15
    lea rdi, [entropy_hist]    ; zero the histogram
    xor eax, eax
    mov ecx, 256
    cld
    rep stosq
    mov r13, [shdr + SH_SIZE]  ; bytes still to read
    xor r15, r15               ; total bytes counted
    test r13, r13
    jz .se_zero
    mov rdi, r12               ; seek to the section data
    mov rsi, [shdr + SH_OFFSET]
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
.se_read:
    test r13, r13
    jz .se_compute
    mov rdx, DUMP_CHUNK        ; n = min(chunk, remaining)
    cmp r13, rdx
    jae .se_have
    mov rdx, r13
.se_have:
    mov rdi, r12
    lea rsi, [dump_buf]
    mov rax, SYS_READ
    syscall
    test rax, rax
    jle .se_compute            ; EOF / error: use what we have
    mov r14, rax
    add r15, r14
    sub r13, r14
    lea rsi, [dump_buf]
    lea rbx, [entropy_hist]    ; base register: avoids abs32 section-crossing reloc
    xor rcx, rcx
.se_tally:
    cmp rcx, r14
    jae .se_read
    movzx eax, byte [rsi + rcx]
    inc qword [rbx + rax*8]
    inc rcx
    jmp .se_tally
.se_compute:
    test r15, r15
    jz .se_zero
    xor rbx, rbx               ; sum_i count_i*log2(count_i)  (Q16)
    xor r13, r13               ; i = 0..255
.se_sum:
    cmp r13, 256
    jae .se_final
    lea rax, [entropy_hist]
    mov r14, [rax + r13*8]
    test r14, r14
    jz .se_sum_next
    mov rax, r14
    call log2_fp               ; Q16 log2(count)
    imul rax, r14
    add rbx, rax
.se_sum_next:
    inc r13
    jmp .se_sum
.se_final:
    mov rax, r15               ; log2(total)  (Q16)
    call log2_fp
    mov r14, rax
    mov rax, rbx               ; sum / total  (Q16)
    xor rdx, rdx
    div r15
    sub r14, rax               ; H = log2(total) - sum/total  (Q16)
    jns .se_scale
    xor r14, r14               ; clamp tiny negative rounding to 0
.se_scale:
    mov rax, r14               ; thousandths = round(H * 1000 / 65536)
    imul rax, 1000
    add rax, 32768
    shr rax, 16
    jmp .se_ret
.se_zero:
    xor eax, eax
.se_ret:
    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; print_entropy_value - print a thousandths value as "D.DDD".
;   in: rax = value in thousandths (0..8000+)
;   clobbers rax, rcx, rdx
print_entropy_value:
    xor rdx, rdx
    mov rcx, 1000
    div rcx                    ; rax = integer part, rdx = fraction 0..999
    push rdx
    call print_dec
    PRINT dot_str
    pop rax                    ; fraction
    xor rdx, rdx
    mov rcx, 100
    div rcx                    ; hundreds
    add al, '0'
    mov [frac_buf], al
    mov rax, rdx
    xor rdx, rdx
    mov rcx, 10
    div rcx                    ; tens, units
    add al, '0'
    mov [frac_buf + 1], al
    add dl, '0'
    mov [frac_buf + 2], dl
    mov byte [frac_buf + 3], 0
    PRINT frac_buf
    ret

; analyze_entropy - the "Entropy:" text report (one line per data section).
;   r12=fd, r13=section index, r14=lines printed, r15=section count.
analyze_entropy:
    movzx r15d, word [ehdr + E_SHNUM]
    test r15, r15
    jz .ae_none
    call load_shstrtab
    PRINT ent_title
    xor r13, r13
    xor r14, r14
.ae_loop:
    cmp r13, r15
    jae .ae_done
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
    jl .ae_done
    mov eax, dword [shdr + SH_TYPE]
    cmp eax, SHT_NULL
    je .ae_next
    cmp eax, SHT_NOBITS
    je .ae_next
    cmp qword [shdr + SH_SIZE], 0
    je .ae_next
    call section_entropy       ; rax = thousandths
    push rax
    PRINT ent_indent
    pop rax
    push rax
    call print_entropy_value
    PRINT ent_bits
    call section_name_ptr
    call print_cstr
    pop rax                    ; entropy
    cmp rax, ENTROPY_PACK_THRESH
    jb .ae_eol
    test qword [shdr + SH_FLAGS], SHF_EXECINSTR
    jz .ae_eol
    PRINT ent_high
.ae_eol:
    PRINT nl
    inc r14
.ae_next:
    inc r13
    jmp .ae_loop
.ae_done:
    test r14, r14
    jnz .ae_ret
    PRINT ent_none
.ae_ret:
    ret
.ae_none:
    PRINT ent_title
    PRINT ent_none
    ret

; json_entropy - "entropy":{"sections":[{"name","size","entropy","packed"}...]}
json_entropy:
    PRINT jk_entropy
    PRINT j_lbrace
    PRINT jk_sections
    PRINT j_lbrack
    movzx r15d, word [ehdr + E_SHNUM]
    test r15, r15
    jz .je_close
    call load_shstrtab
    xor r13, r13
    xor r14, r14               ; emitted count (comma control)
.je_loop:
    cmp r13, r15
    jae .je_close
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
    jl .je_close
    mov eax, dword [shdr + SH_TYPE]
    cmp eax, SHT_NULL
    je .je_next
    cmp eax, SHT_NOBITS
    je .je_next
    cmp qword [shdr + SH_SIZE], 0
    je .je_next
    call section_entropy
    push rax
    test r14, r14
    jz .je_obj
    PRINT j_comma
.je_obj:
    PRINT j_lbrace
    PRINT jk_name
    call section_name_ptr
    call jstr
    PRINT j_comma
    PRINT jk_size
    mov rax, [shdr + SH_SIZE]
    call print_dec
    PRINT j_comma
    PRINT jk_entropy
    mov rax, [rsp]             ; peek entropy
    call print_entropy_value
    PRINT j_comma
    PRINT jk_packed
    pop rax                    ; entropy
    cmp rax, ENTROPY_PACK_THRESH
    jb .je_notpacked
    test qword [shdr + SH_FLAGS], SHF_EXECINSTR
    jz .je_notpacked
    PRINT j_true
    jmp .je_endobj
.je_notpacked:
    PRINT j_false
.je_endobj:
    PRINT j_rbrace
    inc r14
.je_next:
    inc r13
    jmp .je_loop
.je_close:
    PRINT j_rbrack
    PRINT j_rbrace
    ret

; scan_packed_sections - set [tri_packed] if any executable PROGBITS section
;   large enough to be meaningful exceeds the entropy threshold.  Silent.
scan_packed_sections:
    mov byte [tri_packed], 0
    push rbx
    push r13
    push r14
    push r15
    movzx r15d, word [ehdr + E_SHNUM]
    test r15, r15
    jz .sps_pop
    xor r13, r13
.sps_loop:
    cmp r13, r15
    jae .sps_pop
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
    jl .sps_pop
    test qword [shdr + SH_FLAGS], SHF_EXECINSTR
    jz .sps_next
    cmp dword [shdr + SH_TYPE], SHT_PROGBITS
    jne .sps_next
    cmp qword [shdr + SH_SIZE], ENTROPY_MIN_SIZE
    jb .sps_next
    call section_entropy
    cmp rax, ENTROPY_PACK_THRESH
    jb .sps_next
    mov byte [tri_packed], 1
    jmp .sps_pop               ; one hit is enough
.sps_next:
    inc r13
    jmp .sps_loop
.sps_pop:
    pop r15
    pop r14
    pop r13
    pop rbx
    ret
