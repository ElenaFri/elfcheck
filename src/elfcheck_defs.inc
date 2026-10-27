; ---- Linux x86-64 syscall numbers ----
%define SYS_READ   0
%define SYS_WRITE  1
%define SYS_OPEN   2
%define SYS_CLOSE  3
%define SYS_LSEEK  8
%define SYS_EXIT   60

%define SEEK_SET   0
%define SEEK_END   2

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
%define E_VERSION   20
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
%define ELFCLASS64  2
%define ELFDATA2LSB 1
%define EV_CURRENT  1

; ---- program header field offsets (Elf64_Phdr, 56 bytes) ----
%define PHDR_SIZE   56
%define P_TYPE      0
%define P_FLAGS     4
%define P_OFFSET    8
%define P_VADDR     16
%define P_FILESZ    32
%define P_MEMSZ     40
%define P_ALIGN     48
%define PT_GNU_STACK 0x6474e551
%define PT_INTERP    3
%define PT_NOTE      4
%define PT_GNU_RELRO 0x6474e552
%define PT_GNU_PROPERTY 0x6474e553
%define SHT_NOTE     7
%define NT_GNU_PROPERTY_TYPE_0 5
%define GNU_PROPERTY_X86_FEATURE_1_AND 0xc0000002
%define GNU_PROPERTY_X86_FEATURE_1_IBT 1
%define GNU_PROPERTY_X86_FEATURE_1_SHSTK 2
%define PF_X        1
%define PF_W        2
%define PF_R        4

; ---- e_type values and dynamic-section tags (for the hardening report) ----
%define ET_REL       1
%define ET_EXEC      2
%define ET_DYN       3
%define DT_RPATH     15
%define DT_BIND_NOW  24
%define DT_RUNPATH   29
%define DT_FLAGS     30
%define DT_FLAGS_1   0x6ffffffb
%define DF_BIND_NOW  0x8
%define DF_1_NOW     0x1

; ---- section-selection filter bits (0 = use the standard report) ----
%define FILT_HEADER    1
%define FILT_SEGMENTS  2
%define FILT_SECTIONS  4
%define FILT_VALIDATE  8
%define FILT_SECURITY  16
%define FILT_DYNAMIC   32
%define FILT_HARDENING 64
%define FILT_SYMBOLS   128
%define FILT_RELOCS    256
%define FILT_DEFAULT   0x7f

; ---- program header table column widths ----
%define W_IDX       5
%define W_TYPE      15
%define W_FLAGS     7
%define W_OFF       14
%define W_VADDR     14
%define W_FILESZ    14
%define W_MEMSZ     14

; ---- section header field offsets (Elf64_Shdr, 64 bytes) ----
%define SHDR_SIZE    64
%define SH_NAME      0
%define SH_TYPE      4
%define SH_FLAGS     8
%define SH_ADDR      16
%define SH_OFFSET    24
%define SH_SIZE      32
%define SH_LINK      40
%define SH_INFO      44
%define SH_ENTSIZE   56
%define SH_ADDRALIGN 48
%define SHF_WRITE    0x1
%define SHF_EXECINSTR 0x4

; ---- section header table column widths ----
%define WS_IDX      5
%define WS_NAME     20
%define WS_TYPE     16
%define WS_FLAGS    7
%define WS_ADDR     14
%define WS_OFFSET   14
%define WS_SIZE     14

; max bytes of the section-name string table we buffer
%define STRTAB_CAP  32768

; max bytes of an executable section we disassemble
%define TEXT_CAP    262144
%define FUNC_CACHE_CAP 8192
%define RELOC_CACHE_CAP 8192

; max bytes of the dynamic string table we buffer
%define DYNSTR_CAP  262144

; GNU symbol-version sections use 15-bit version indexes.
%define VER_MAP_COUNT 32768
%define VERSTR_CAP    65536

; operand rendering styles for the disassembler
%define ST_NONE     0
%define ST_RM_REG   1          ; r/m, reg
%define ST_REG_RM   2          ; reg, r/m
%define ST_RM_IMM   3          ; r/m, imm
%define ST_RM       4          ; r/m
%define ST_REG_IMM  5          ; reg-in-opcode, imm
%define ST_OREG     6          ; reg-in-opcode
%define ST_ACC_IMM  7          ; al/eax/rax, imm
%define ST_REL      8          ; relative branch target
%define ST_IMM      9          ; imm only
%define ST_RM_1     10         ; r/m, 1          (shift by one)
%define ST_RM_CL    11         ; r/m, cl         (shift by cl)
%define ST_REG_RM_B 12         ; reg, r/m (movzx/movsx: dest wide, src byte/word)
%define ST_REG_RM_IMM 13       ; reg, r/m, imm (imul)

default rel

; Print a NUL-terminated string at %1 to stdout.
%macro PRINT 1
    lea rsi, [%1]
    call print_cstr
%endmacro

; Like PRINT, but suppressed when [silent] is set (used by validate_structure
; so it can double as a silent issue counter for the JSON output path).
%macro VP 1
    lea rsi, [%1]
    call vprint
%endmacro

; Argument-parsing helpers, expanded inside _start (rcx=i, r9=&argv[0]).
; MODEARG: if argv[i] == %1, set byte [%2]=1 and advance to the next arg.
%macro MODEARG 2
    mov rsi, [r9 + rcx*8]
    lea rdi, [%1]
    call streq
    test al, al
    jz %%skip
    mov byte [%2], 1
    jmp .arg_next
%%skip:
%endmacro

; FILTARG: if argv[i] == %1, OR the filter bit %2 into [filter_mask] and advance.
%macro FILTARG 2
    mov rsi, [r9 + rcx*8]
    lea rdi, [%1]
    call streq
    test al, al
    jz %%skip
    or dword [filter_mask], %2
    jmp .arg_next
%%skip:
%endmacro

