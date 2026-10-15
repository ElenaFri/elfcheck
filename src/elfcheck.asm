; elfcheck - minimal ELF64 inspector
; Linux x86-64, NASM syntax.
;
; Validates the ELF magic and parses/displays the ELF64 file header
; (Elf64_Ehdr): class, endianness, OS/ABI, type, machine, entry point,
; header/table offsets, and table entry sizes/counts. Program headers and
; section headers will build on top of this.
;
; Exit codes:
;   0  valid ELF, header displayed
;   1  usage error / cannot open / cannot read / not an ELF / truncated header

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

; ---- ELF header size and field offsets (Elf64_Ehdr) ----
%define EHDR_SIZE   64
%define EI_CLASS    4
%define EI_DATA     5
%define EI_VERSION  6
%define EI_OSABI    7
%define E_TYPE      16
%define E_MACHINE   18
%define E_ENTRY     24
%define E_PHOFF     32
%define E_SHOFF     40
%define E_FLAGS     48
%define E_EHSIZE    52
%define E_PHENTSIZE 54
%define E_PHNUM     56
%define E_SHENTSIZE 58
%define E_SHNUM     60
%define E_SHSTRNDX  62

default rel

; Print a NUL-terminated string at %1 to stdout.
%macro PRINT 1
    lea rsi, [%1]
    call print_cstr
%endmacro

section .rodata
    elf_magic:      db 0x7f, 'E', 'L', 'F'

    usage_msg:      db "Usage: elfcheck <file>", 10
    usage_len:      equ $ - usage_msg

    open_err_msg:   db "elfcheck: error: cannot open file", 10
    open_err_len:   equ $ - open_err_msg

    read_err_msg:   db "elfcheck: error: cannot read file", 10
    read_err_len:   equ $ - read_err_msg

    invalid_msg:    db "elfcheck: not an ELF file (bad magic)", 10
    invalid_len:    equ $ - invalid_msg

    trunc_msg:      db "elfcheck: error: truncated ELF header", 10
    trunc_len:      equ $ - trunc_msg

    ; ---- header labels (aligned, NUL-terminated, no newline) ----
    hdr_title:      db "ELF Header:", 10, 0
    nl:             db 10, 0

    l_class:        db "  Class:                     ", 0
    l_data:         db "  Data:                      ", 0
    l_version:      db "  Version:                   ", 0
    l_osabi:        db "  OS/ABI:                    ", 0
    l_type:         db "  Type:                      ", 0
    l_machine:      db "  Machine:                   ", 0
    l_entry:        db "  Entry point:               ", 0
    l_phoff:        db "  Program header offset:     ", 0
    l_shoff:        db "  Section header offset:     ", 0
    l_flags:        db "  Flags:                     ", 0
    l_ehsize:       db "  ELF header size:           ", 0
    l_phentsize:    db "  Program header entry size: ", 0
    l_phnum:        db "  Program header count:      ", 0
    l_shentsize:    db "  Section header entry size: ", 0
    l_shnum:        db "  Section header count:      ", 0
    l_shstrndx:     db "  Section name index:        ", 0

    ; ---- enum value names ----
    s_class32:      db "ELF32", 0
    s_class64:      db "ELF64", 0
    s_class_inv:    db "invalid", 0

    s_data_le:      db "little-endian (2's complement)", 0
    s_data_be:      db "big-endian (2's complement)", 0
    s_data_inv:     db "invalid", 0

    s_osabi_sysv:   db "UNIX - System V", 0
    s_osabi_linux:  db "Linux", 0
    s_osabi_other:  db "other", 0

    s_type_none:    db "NONE (No file type)", 0
    s_type_rel:     db "REL (Relocatable file)", 0
    s_type_exec:    db "EXEC (Executable file)", 0
    s_type_dyn:     db "DYN (Shared object / PIE)", 0
    s_type_core:    db "CORE (Core file)", 0
    s_type_unknown: db "UNKNOWN", 0

    s_mach_386:     db "Intel 80386", 0
    s_mach_x8664:   db "AMD x86-64", 0
    s_mach_arm:     db "ARM", 0
    s_mach_aarch64: db "AArch64", 0
    s_mach_riscv:   db "RISC-V", 0
    s_mach_unknown: db "unknown", 0

section .bss
    ehdr:           resb EHDR_SIZE     ; full ELF header
    nread:          resq 1             ; bytes actually read
    numbuf:         resb 32            ; scratch for number formatting

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

    mov rdi, r12             ; read the header
    mov rax, SYS_READ
    lea rsi, [ehdr]
    mov rdx, EHDR_SIZE
    syscall
    cmp rax, 4               ; need at least the 4 magic bytes
    jl .read_error
    mov [nread], rax

    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall

    mov eax, dword [ehdr]      ; validate magic
    cmp eax, dword [elf_magic]
    jne .invalid

    cmp qword [nread], EHDR_SIZE
    jl .truncated

    call print_header
    xor edi, edi
    jmp .exit

.invalid:
    lea rsi, [invalid_msg]
    mov rdx, invalid_len
    call print_stderr
    mov edi, 1
    jmp .exit

.truncated:
    lea rsi, [trunc_msg]
    mov rdx, trunc_len
    call print_stderr
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

; ---------------------------------------------------------------------------
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
; print_hex - print "0x" + minimal-width hex of rax to stdout
; ---------------------------------------------------------------------------
print_hex:                 ; in: rax = value
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
    lea rsi, [numbuf]
    mov rdx, rbx
    sub rdx, rsi
    call print_str
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; print_dec - print unsigned decimal of rax to stdout
; ---------------------------------------------------------------------------
print_dec:                 ; in: rax = value
    push rbx
    mov rcx, 10
    lea rbx, [numbuf + 31] ; build digits backward from the end
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
    lea rax, [numbuf + 32]
    sub rax, rbx
    mov rdx, rax
    call print_str
    pop rbx
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
; print_str / print_stderr - write(fd, rsi, rdx)
; ---------------------------------------------------------------------------
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
