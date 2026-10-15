; elfcheck - minimal ELF64 inspector skeleton
; Linux x86-64, NASM syntax.
;
; This is the project bootstrap: it validates the full build/link pipeline
; and implements the first feature (ELF magic validation). Parsing of the
; ELF header, program headers and section headers will build on top of this.
;
; Exit codes:
;   0  valid ELF magic
;   1  usage error / cannot open / cannot read / not an ELF file

; ---- Linux x86-64 syscall numbers ----
%define SYS_READ   0
%define SYS_WRITE  1
%define SYS_OPEN   2
%define SYS_CLOSE  3
%define SYS_EXIT   60

; ---- File descriptors ----
%define STDOUT     1
%define STDERR     2

; ---- open() flags ----
%define O_RDONLY   0

; ---- ELF constants ----
%define EI_NIDENT  16

default rel

section .rodata
    elf_magic:      db 0x7f, 'E', 'L', 'F'

    usage_msg:      db "Usage: elfcheck <file>", 10
    usage_len:      equ $ - usage_msg

    open_err_msg:   db "elfcheck: error: cannot open file", 10
    open_err_len:   equ $ - open_err_msg

    read_err_msg:   db "elfcheck: error: cannot read file", 10
    read_err_len:   equ $ - read_err_msg

    valid_msg:      db "valid ELF64 magic detected", 10
    valid_len:      equ $ - valid_msg

    invalid_msg:    db "not an ELF file (bad magic)", 10
    invalid_len:    equ $ - invalid_msg

section .bss
    e_ident:        resb EI_NIDENT

section .text
    global _start

_start:
    mov rax, [rsp]             ; argc
    cmp rax, 2
    jne .usage

    mov rdi, [rsp + 16]       ; argv[1] -> path
    mov rax, SYS_OPEN
    xor esi, esi              ; O_RDONLY
    xor edx, edx
    syscall
    test rax, rax
    js .open_error
    mov r12, rax              ; save fd

    mov rdi, r12             ; read e_ident
    mov rax, SYS_READ
    lea rsi, [e_ident]
    mov rdx, EI_NIDENT
    syscall
    cmp rax, 4               ; need at least the 4 magic bytes
    jl .read_error

    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall

    mov eax, dword [e_ident]   ; compare 4 magic bytes
    cmp eax, dword [elf_magic]
    jne .invalid

    lea rsi, [valid_msg]
    mov rdx, valid_len
    call print_stdout
    xor edi, edi
    jmp .exit

.invalid:
    lea rsi, [invalid_msg]
    mov rdx, invalid_len
    call print_stdout
    mov edi, 1
    jmp .exit

.usage:
    lea rsi, [usage_msg]
    mov rdx, usage_len
    call print_stderr
    mov edi, 1
    jmp .exit

.open_error:
    lea rsi, [open_err_msg]
    mov rdx, open_err_len
    call print_stderr
    mov edi, 1
    jmp .exit

.read_error:
    mov rdi, r12
    mov rax, SYS_CLOSE
    syscall
    lea rsi, [read_err_msg]
    mov rdx, read_err_len
    call print_stderr
    mov edi, 1
    jmp .exit

.exit:
    mov rax, SYS_EXIT
    syscall

; ---- helpers ----
; print_stdout / print_stderr
;   in: rsi = buffer, rdx = length
print_stdout:
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    syscall
    ret

print_stderr:
    mov rax, SYS_WRITE
    mov rdi, STDERR
    syscall
    ret
