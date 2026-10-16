; elfcheck - minimal ELF64 inspector
; Linux x86-64, NASM syntax.
;
; Validates the ELF magic and parses/displays the ELF64 file header
; (Elf64_Ehdr), the program headers and the section headers, then performs
; structural validation (offsets, table bounds, segment/section file ranges).
; With --json the whole analysis is emitted as a single-line JSON object.
;
; Exit codes:
;   0  valid ELF, no structural issues detected
;   1  usage error / cannot open / cannot read / not an ELF / truncated header
;   2  valid ELF header, but structural inconsistencies were found

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
%define PT_GNU_RELRO 0x6474e552
%define PF_X        1
%define PF_W        2
%define PF_R        4

; ---- e_type values and dynamic-section tags (for the hardening report) ----
%define ET_EXEC      2
%define ET_DYN       3
%define DT_RPATH     15
%define DT_BIND_NOW  24
%define DT_RUNPATH   29
%define DT_FLAGS     30
%define DT_FLAGS_1   0x6ffffffb
%define DF_BIND_NOW  0x8
%define DF_1_NOW     0x1

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

; max bytes of the dynamic string table we buffer
%define DYNSTR_CAP  262144

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

section .rodata
    elf_magic:      db 0x7f, 'E', 'L', 'F'

    usage_msg:      db "Usage: elfcheck [--json] <file>", 10
    usage_len:      equ $ - usage_msg

    opt_json:       db "--json", 0

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

    ; ---- program header display ----
    ph_title:       db 10, "Program Headers:", 10, 0
    two_spaces:     db "  ", 0
    col_idx:        db "Idx", 0
    col_type:       db "Type", 0
    col_flags:      db "Flags", 0
    col_offset:     db "Offset", 0
    col_vaddr:      db "VirtAddr", 0
    col_filesz:     db "FileSize", 0
    col_memsz:      db "MemSize", 0
    col_align:      db "Align", 0
    col_name:       db "Name", 0
    col_addr:       db "Addr", 0
    col_size:       db "Size", 0
    spaces:         db "                                ", 0  ; 32 spaces for padding
    empty_str:      db 0

    ; ---- section header display ----
    sh_title:       db 10, "Section Headers:", 10, 0

    ; ---- section header type names ----
    sht_null:       db "NULL", 0
    sht_progbits:   db "PROGBITS", 0
    sht_symtab:     db "SYMTAB", 0
    sht_strtab:     db "STRTAB", 0
    sht_rela:       db "RELA", 0
    sht_hash:       db "HASH", 0
    sht_dynamic:    db "DYNAMIC", 0
    sht_note:       db "NOTE", 0
    sht_nobits:     db "NOBITS", 0
    sht_rel:        db "REL", 0
    sht_dynsym:     db "DYNSYM", 0
    sht_init_arr:   db "INIT_ARRAY", 0
    sht_fini_arr:   db "FINI_ARRAY", 0
    sht_preinit:    db "PREINIT_ARRAY", 0
    sht_group:      db "GROUP", 0
    sht_gnu_hash:   db "GNU_HASH", 0
    sht_verdef:     db "VERDEF", 0
    sht_verneed:    db "VERNEED", 0
    sht_versym:     db "VERSYM", 0
    sht_unknown:    db "UNKNOWN", 0

    ; ---- structural validation ----
    val_title:      db 10, "Validation:", 10, 0
    val_mark:       db "  [!] ", 0
    val_ok:         db "  [ok] no structural issues detected", 10, 0
    m_ehsize:       db "unexpected e_ehsize=", 0
    m_exp64:        db " (expected 64)", 0
    m_phentsize:    db "unexpected e_phentsize=", 0
    m_exp56:        db " (expected 56)", 0
    m_shentsize:    db "unexpected e_shentsize=", 0
    m_shstrndx:     db "e_shstrndx=", 0
    m_oorange:      db " out of range (shnum=", 0
    m_phtab:        db "program header table extends past end of file", 10, 0
    m_shtab:        db "section header table extends past end of file", 10, 0
    m_seg:          db "segment ", 0
    m_sect:         db "section ", 0
    m_past_off:     db " extends past end of file (off=", 0
    m_filesz:       db " filesz=", 0
    m_size:         db " size=", 0
    m_fmgt:         db " has p_filesz > p_memsz", 0
    m_rparen:       db ")", 0
    m_issues:       db " issue(s) found", 10, 0

    ; ---- security analysis messages ----
    sec_title:      db 10, "Security:", 10, 0
    sec_ok:         db "  [ok] no security concerns detected", 10, 0
    s_execstack:    db "  [!] executable stack (PT_GNU_STACK carries the X flag)", 10, 0
    s_nostack:      db "  [!] no PT_GNU_STACK segment (stack executability unspecified)", 10, 0
    s_wx_pre:       db "  [!] segment ", 0
    s_wx_post:      db " is writable and executable (W^X violation)", 10, 0
    s_entry_pre:    db "  [!] entry point ", 0
    s_entry_post:   db " is not inside any executable segment", 10, 0
    s_wxsect_pre:   db "  [!] section ", 0
    s_wxsect_post:  db " is writable and executable", 10, 0
    s_noshdr:       db "  [!] no section header table (section info stripped)", 10, 0
    sec_summary:    db " security warning(s) found", 10, 0

    ; ---- dynamic linking analysis ----
    dyn_title:      db 10, "Dynamic:", 10, 0
    dyn_static:     db "  statically linked (no dynamic section)", 10, 0
    dyn_nosh:       db "  no section headers; dynamic info unavailable", 10, 0
    dyn_needed_hdr: db "  Needed libraries:", 10, 0
    dyn_imports_hdr:db "  Imported symbols:", 10, 0
    dyn_none:       db "    (none)", 10, 0
    dyn_indent:     db "    ", 0

    ; ---- hardening report (checksec-style) ----
    hd_title:       db 10, "Hardening:", 10, 0
    hd_relro_lbl:   db "  RELRO:         ", 0
    hd_canary_lbl:  db "  Stack canary:  ", 0
    hd_nx_lbl:      db "  NX:            ", 0
    hd_pie_lbl:     db "  PIE:           ", 0
    hd_rpath_lbl:   db "  RPATH:         ", 0
    hd_runpath_lbl: db "  RUNPATH:       ", 0
    hd_fortify_lbl: db "  Fortify:       ", 0
    hd_full:        db "full", 10, 0
    hd_partial:     db "partial", 10, 0
    hd_none:        db "none", 10, 0
    hd_yes:         db "found", 10, 0
    hd_no:          db "not found", 10, 0
    hd_enabled:     db "enabled", 10, 0
    hd_disabled:    db "disabled", 10, 0
    hd_unknown:     db "unknown (no PT_GNU_STACK)", 10, 0
    hd_dso:         db "shared object", 10, 0
    hd_na:          db "n/a", 10, 0
    hd_notset:      db "not set", 10, 0
    hd_fortify_fns: db " fortified function(s)", 10, 0
    name_stackchk:  db "__stack_chk_fail", 0

    ; ---- program header (segment) type names ----
    pt_null:        db "NULL", 0
    pt_load:        db "LOAD", 0
    pt_dynamic:     db "DYNAMIC", 0
    pt_interp:      db "INTERP", 0
    pt_note:        db "NOTE", 0
    pt_phdr:        db "PHDR", 0
    pt_tls:         db "TLS", 0
    pt_ehframe:     db "GNU_EH_FRAME", 0
    pt_gnustack:    db "GNU_STACK", 0
    pt_gnurelro:    db "GNU_RELRO", 0
    pt_gnuprop:     db "GNU_PROPERTY", 0
    pt_unknown:     db "UNKNOWN", 0

    ; ---- JSON output tokens ----
    j_lbrace:       db "{", 0
    j_rbrace:       db "}", 0
    j_lbrack:       db "[", 0
    j_rbrack:       db "]", 0
    j_comma:        db ",", 0
    j_quote:        db 34, 0
    j_true:         db "true", 0
    j_false:        db "false", 0
    j_null:         db "null", 0
    esc_quote:      db 92, 34, 0            ; backslash + double-quote
    esc_bslash:     db 92, 92, 0            ; two backslashes
    esc_u00:        db 92, "u00", 0         ; prefix for control-char escapes

    ; JSON object keys (each renders as "name":)
    jk_header:      db 34, "header", 34, ":", 0
    jk_phdrs:       db 34, "program_headers", 34, ":", 0
    jk_shdrs:       db 34, "section_headers", 34, ":", 0
    jk_validation:  db 34, "validation", 34, ":", 0
    jk_class:       db 34, "class", 34, ":", 0
    jk_data:        db 34, "data", 34, ":", 0
    jk_osabi:       db 34, "osabi", 34, ":", 0
    jk_type:        db 34, "type", 34, ":", 0
    jk_machine:     db 34, "machine", 34, ":", 0
    jk_entry:       db 34, "entry", 34, ":", 0
    jk_phoff:       db 34, "phoff", 34, ":", 0
    jk_shoff:       db 34, "shoff", 34, ":", 0
    jk_flags:       db 34, "flags", 34, ":", 0
    jk_ehsize:      db 34, "ehsize", 34, ":", 0
    jk_phentsize:   db 34, "phentsize", 34, ":", 0
    jk_phnum:       db 34, "phnum", 34, ":", 0
    jk_shentsize:   db 34, "shentsize", 34, ":", 0
    jk_shnum:       db 34, "shnum", 34, ":", 0
    jk_shstrndx:    db 34, "shstrndx", 34, ":", 0
    jk_index:       db 34, "index", 34, ":", 0
    jk_offset:      db 34, "offset", 34, ":", 0
    jk_vaddr:       db 34, "vaddr", 34, ":", 0
    jk_filesz:      db 34, "filesz", 34, ":", 0
    jk_memsz:       db 34, "memsz", 34, ":", 0
    jk_align:       db 34, "align", 34, ":", 0
    jk_name:        db 34, "name", 34, ":", 0
    jk_addr:        db 34, "addr", 34, ":", 0
    jk_size:        db 34, "size", 34, ":", 0
    jk_addralign:   db 34, "addralign", 34, ":", 0
    jk_issues:      db 34, "issues", 34, ":", 0
    jk_valid:       db 34, "valid", 34, ":", 0
    jk_security:    db 34, "security", 34, ":", 0
    jk_gnustack:    db 34, "gnu_stack", 34, ":", 0
    jk_execstack:   db 34, "executable_stack", 34, ":", 0
    jk_wxseg:       db 34, "wx_segments", 34, ":", 0
    jk_wxsect:      db 34, "wx_sections", 34, ":", 0
    jk_entryok:     db 34, "entry_in_exec", 34, ":", 0
    jk_hasshdr:     db 34, "has_section_headers", 34, ":", 0
    jk_warnings:    db 34, "warnings", 34, ":", 0
    jv_st_absent:   db "absent", 0
    jv_st_noexec:   db "noexec", 0
    jv_st_exec:     db "exec", 0
    jk_dynamic:     db 34, "dynamic", 34, ":", 0
    jk_static:      db 34, "static", 34, ":", 0
    jk_needed:      db 34, "needed", 34, ":", 0
    jk_imports:     db 34, "imports", 34, ":", 0
    jk_hardening:   db 34, "hardening", 34, ":", 0
    jk_relro:       db 34, "relro", 34, ":", 0
    jk_canary:      db 34, "stack_canary", 34, ":", 0
    jk_nx:          db 34, "nx", 34, ":", 0
    jk_pie:         db 34, "pie", 34, ":", 0
    jk_rpath:       db 34, "rpath", 34, ":", 0
    jk_runpath:     db 34, "runpath", 34, ":", 0
    jk_fortify:     db 34, "fortify", 34, ":", 0
    jv_full:        db "full", 0
    jv_partial:     db "partial", 0
    jv_none:        db "none", 0
    jv_enabled:     db "enabled", 0
    jv_disabled:    db "disabled", 0
    jv_unknown:     db "unknown", 0
    jv_dso:         db "shared_object", 0
    jv_na:          db "n/a", 0

    ; ---- disassembler literals ----
    dis_title:      db 10, "Disassembly of section ", 0
    dis_colon_nl:   db ":", 10, 0
    dis_nosect:     db "elfcheck: no executable .text section to disassemble", 10
    dis_nosect_len: equ $ - dis_nosect
    dis_trunc_note: db "  ... (section larger than buffer; output truncated)", 10, 0
    dis_colon:      db ":", 0
    dis_space:      db " ", 0
    dis_comma:      db ", ", 0
    dis_0x:         db "0x", 0
    dis_lbr:        db "[", 0
    dis_rbr:        db "]", 0
    dis_plus:       db "+", 0
    dis_minus:      db "-", 0
    dis_star:       db "*", 0
    dis_rip:        db "rip", 0
    dis_byte_db:    db ".byte ", 0
    dis_pad:        db "                                        ", 0 ; 40 spaces
    dis_one:        db "1", 0
    dis_cl:         db "cl", 0
    name_text:      db ".text", 0

    ; size keywords indexed by log2(size): 0->byte 1->word 2->dword 3->qword
    sz_byte:        db "byte ", 0
    sz_word:        db "word ", 0
    sz_dword:       db "dword ", 0
    sz_qword:       db "qword ", 0
    sz_tbl:         dq sz_byte, sz_word, sz_dword, sz_qword

    ; general-purpose register names
    r64_0:  db "rax",0
    r64_1:  db "rcx",0
    r64_2:  db "rdx",0
    r64_3:  db "rbx",0
    r64_4:  db "rsp",0
    r64_5:  db "rbp",0
    r64_6:  db "rsi",0
    r64_7:  db "rdi",0
    r64_8:  db "r8",0
    r64_9:  db "r9",0
    r64_10: db "r10",0
    r64_11: db "r11",0
    r64_12: db "r12",0
    r64_13: db "r13",0
    r64_14: db "r14",0
    r64_15: db "r15",0
    regs64: dq r64_0,r64_1,r64_2,r64_3,r64_4,r64_5,r64_6,r64_7
            dq r64_8,r64_9,r64_10,r64_11,r64_12,r64_13,r64_14,r64_15

    r32_0:  db "eax",0
    r32_1:  db "ecx",0
    r32_2:  db "edx",0
    r32_3:  db "ebx",0
    r32_4:  db "esp",0
    r32_5:  db "ebp",0
    r32_6:  db "esi",0
    r32_7:  db "edi",0
    r32_8:  db "r8d",0
    r32_9:  db "r9d",0
    r32_10: db "r10d",0
    r32_11: db "r11d",0
    r32_12: db "r12d",0
    r32_13: db "r13d",0
    r32_14: db "r14d",0
    r32_15: db "r15d",0
    regs32: dq r32_0,r32_1,r32_2,r32_3,r32_4,r32_5,r32_6,r32_7
            dq r32_8,r32_9,r32_10,r32_11,r32_12,r32_13,r32_14,r32_15

    r16_0:  db "ax",0
    r16_1:  db "cx",0
    r16_2:  db "dx",0
    r16_3:  db "bx",0
    r16_4:  db "sp",0
    r16_5:  db "bp",0
    r16_6:  db "si",0
    r16_7:  db "di",0
    r16_8:  db "r8w",0
    r16_9:  db "r9w",0
    r16_10: db "r10w",0
    r16_11: db "r11w",0
    r16_12: db "r12w",0
    r16_13: db "r13w",0
    r16_14: db "r14w",0
    r16_15: db "r15w",0
    regs16: dq r16_0,r16_1,r16_2,r16_3,r16_4,r16_5,r16_6,r16_7
            dq r16_8,r16_9,r16_10,r16_11,r16_12,r16_13,r16_14,r16_15

    r8_0:   db "al",0
    r8_1:   db "cl",0
    r8_2:   db "dl",0
    r8_3:   db "bl",0
    r8_4:   db "spl",0
    r8_5:   db "bpl",0
    r8_6:   db "sil",0
    r8_7:   db "dil",0
    r8_8:   db "r8b",0
    r8_9:   db "r9b",0
    r8_10:  db "r10b",0
    r8_11:  db "r11b",0
    r8_12:  db "r12b",0
    r8_13:  db "r13b",0
    r8_14:  db "r14b",0
    r8_15:  db "r15b",0
    regs8:  dq r8_0,r8_1,r8_2,r8_3,r8_4,r8_5,r8_6,r8_7
            dq r8_8,r8_9,r8_10,r8_11,r8_12,r8_13,r8_14,r8_15
    ; legacy high-byte names when no REX prefix is present (indices 4-7)
    r8h_4:  db "ah",0
    r8h_5:  db "ch",0
    r8h_6:  db "dh",0
    r8h_7:  db "bh",0
    regs8h: dq r8_0,r8_1,r8_2,r8_3,r8h_4,r8h_5,r8h_6,r8h_7

    ; mnemonics
    mn_add:  db "add",0
    mn_or:   db "or",0
    mn_adc:  db "adc",0
    mn_sbb:  db "sbb",0
    mn_and:  db "and",0
    mn_sub:  db "sub",0
    mn_xor:  db "xor",0
    mn_cmp:  db "cmp",0
    mn_push: db "push",0
    mn_pop:  db "pop",0
    mn_mov:  db "mov",0
    mn_lea:  db "lea",0
    mn_test: db "test",0
    mn_xchg: db "xchg",0
    mn_nop:  db "nop",0
    mn_ret:  db "ret",0
    mn_leave:db "leave",0
    mn_call: db "call",0
    mn_jmp:  db "jmp",0
    mn_inc:  db "inc",0
    mn_dec:  db "dec",0
    mn_not:  db "not",0
    mn_neg:  db "neg",0
    mn_mul:  db "mul",0
    mn_imul: db "imul",0
    mn_div:  db "div",0
    mn_idiv: db "idiv",0
    mn_int3: db "int3",0
    mn_syscall: db "syscall",0
    mn_cdqe: db "cdqe",0
    mn_cqo:  db "cqo",0
    mn_cwde: db "cwde",0
    mn_cdq:  db "cdq",0
    mn_movzx:db "movzx",0
    mn_movsx:db "movsx",0
    mn_movsxd:db "movsxd",0
    mn_rol:  db "rol",0
    mn_ror:  db "ror",0
    mn_rcl:  db "rcl",0
    mn_rcr:  db "rcr",0
    mn_shl:  db "shl",0
    mn_shr:  db "shr",0
    mn_sar:  db "sar",0
    mn_cpuid:db "cpuid",0
    mn_endbr64: db "endbr64",0
    mn_hlt:  db "hlt",0
    ; string-operation base names (indexed 0-4), size suffix + rep prefix
    ; are appended at decode time into strmnem
    str_movs: db "movs",0
    str_cmps: db "cmps",0
    str_stos: db "stos",0
    str_lods: db "lods",0
    str_scas: db "scas",0
    str_tbl:  dq str_movs,str_movs,str_cmps,str_cmps,0,0,str_stos,str_stos,str_lods,str_lods,str_scas,str_scas
    pfx_rep:  db "rep ",0
    pfx_repz: db "repz ",0
    pfx_repnz:db "repnz ",0
    mn_movsxd_pad: db 0

    ; arithmetic group (0x00..0x3F and group1) indexed by reg/row 0-7
    grp_arith: dq mn_add,mn_or,mn_adc,mn_sbb,mn_and,mn_sub,mn_xor,mn_cmp
    ; shift group (0xC0/C1/D0-D3) indexed by reg 0-7
    grp_shift: dq mn_rol,mn_ror,mn_rcl,mn_rcr,mn_shl,mn_shr,mn_shl,mn_sar
    ; group3 (0xF6/F7) indexed by reg 0-7
    grp_f7:    dq mn_test,mn_test,mn_not,mn_neg,mn_mul,mn_imul,mn_div,mn_idiv

    ; conditional-jump mnemonics indexed by tttn (0-15)
    jcc_0:  db "jo",0
    jcc_1:  db "jno",0
    jcc_2:  db "jb",0
    jcc_3:  db "jae",0
    jcc_4:  db "je",0
    jcc_5:  db "jne",0
    jcc_6:  db "jbe",0
    jcc_7:  db "ja",0
    jcc_8:  db "js",0
    jcc_9:  db "jns",0
    jcc_10: db "jp",0
    jcc_11: db "jnp",0
    jcc_12: db "jl",0
    jcc_13: db "jge",0
    jcc_14: db "jle",0
    jcc_15: db "jg",0
    jcc_tbl: dq jcc_0,jcc_1,jcc_2,jcc_3,jcc_4,jcc_5,jcc_6,jcc_7
             dq jcc_8,jcc_9,jcc_10,jcc_11,jcc_12,jcc_13,jcc_14,jcc_15

    set_0:  db "seto",0
    set_1:  db "setno",0
    set_2:  db "setb",0
    set_3:  db "setae",0
    set_4:  db "sete",0
    set_5:  db "setne",0
    set_6:  db "setbe",0
    set_7:  db "seta",0
    set_8:  db "sets",0
    set_9:  db "setns",0
    set_10: db "setp",0
    set_11: db "setnp",0
    set_12: db "setl",0
    set_13: db "setge",0
    set_14: db "setle",0
    set_15: db "setg",0
    set_tbl: dq set_0,set_1,set_2,set_3,set_4,set_5,set_6,set_7
             dq set_8,set_9,set_10,set_11,set_12,set_13,set_14,set_15

    opt_disasm:     db "--disasm", 0
    opt_disasm_s:   db "-d", 0

section .bss
    ehdr:           resb EHDR_SIZE     ; full ELF header
    phdr:           resb 64            ; one program header entry (56 used)
    shdr:           resb 64            ; one section header entry (64 used)
    strtab:         resb STRTAB_CAP + 1 ; section-name string table (+1 NUL)
    strtab_size:    resq 1             ; bytes actually loaded into strtab
    dynstr:         resb DYNSTR_CAP + 1 ; dynamic string table (+1 NUL)
    dynstr_len:     resq 1             ; bytes actually loaded into dynstr
    dynent:         resb 16            ; one Elf64_Dyn entry
    syment:         resb 24            ; one Elf64_Sym entry
    dyn_off:        resq 1             ; .dynamic file offset
    dyn_size:       resq 1             ; .dynamic size
    dyn_link:       resd 1             ; .dynamic sh_link (string table index)
    dsym_off:       resq 1             ; .dynsym file offset
    dsym_size:      resq 1             ; .dynsym size
    dsym_ent:       resq 1             ; .dynsym entry size
    dsym_link:      resd 1             ; .dynsym sh_link (string table index)
    dyn_is_static:  resb 1             ; 1 = no .dynamic section found
    hd_interp:      resb 1             ; 1 = PT_INTERP present
    hd_stack:       resb 1             ; 0 absent / 1 noexec / 2 exec (PT_GNU_STACK)
    hd_relro_seg:   resb 1             ; 1 = PT_GNU_RELRO present
    hd_bindnow:     resb 1             ; 1 = BIND_NOW (full RELRO)
    hd_canary:      resb 1             ; 1 = __stack_chk_fail imported
    hd_flags1:      resq 1             ; DT_FLAGS_1 value
    hd_rpath_off:   resq 1             ; DT_RPATH dynstr offset, or -1
    hd_runpath_off: resq 1             ; DT_RUNPATH dynstr offset, or -1
    hd_fortify:     resq 1             ; count of imported *_chk functions
    filesize:       resq 1             ; total file size (bytes)
    issues:         resq 1             ; count of structural problems found
    warnings:       resq 1             ; count of security concerns found
    sec_wx:         resq 1             ; count of W^X (writable+executable) segments
    sec_wxsect:     resq 1             ; count of writable+executable sections
    sec_stack:      resb 1             ; GNU_STACK: 0=absent 1=non-exec 2=exec
    sec_entry_ok:   resb 1             ; 1 = entry point lies in an exec segment
    flagbuf:        resb 4             ; "RWX" flag string + NUL
    shflagbuf:      resb 16            ; section flag letters + NUL
    nread:          resq 1             ; bytes actually read
    numbuf:         resb 32            ; scratch for number formatting
    json_mode:      resb 1             ; 1 = emit JSON instead of text
    disasm_mode:    resb 1             ; 1 = disassemble .text instead of report
    silent:         resb 1             ; 1 = validate_structure suppresses output
    jbuf:           resb 8             ; scratch for JSON byte escaping

    ; ---- disassembler state ----
    textbuf:        resb TEXT_CAP      ; raw bytes of the section being decoded
    text_len:       resq 1             ; bytes actually loaded into textbuf
    text_vaddr:     resq 1             ; virtual address of textbuf[0]
    text_trunc:     resq 1             ; 1 if the section was larger than TEXT_CAP
    d_cur:          resq 1             ; decode cursor (into textbuf)
    d_start:        resq 1             ; start of current instruction
    d_end:          resq 1             ; textbuf + text_len
    d_vaddr:        resq 1             ; vaddr of current instruction

    ; per-instruction state, wiped as a block before each decode
    dstate:
    d_rex:          resb 1             ; REX byte (0 if absent)
    d_hasrex:       resb 1
    d_opsize:       resb 1             ; 0x66 operand-size prefix seen
    d_addrsz:       resb 1             ; 0x67 address-size prefix seen
    d_rep:          resb 1             ; 0xF3
    d_repne:        resb 1             ; 0xF2
    d_lock:         resb 1             ; 0xF0
    d_seg:          resb 1             ; segment override prefix (0 none)
    d_modrm:        resb 1
    d_mod:          resb 1
    d_reg:          resb 1             ; reg field incl. REX.R (0-15)
    d_rm:           resb 1             ; rm field incl. REX.B (0-15)
    d_mem:          resb 1             ; 1 if ModR/M encodes memory
    d_scale:        resb 1             ; scale exponent (0-3)
    d_index:        resb 1             ; index reg incl. REX.X (0-15)
    d_base:         resb 1             ; base reg incl. REX.B (0-15)
    d_no_base:      resb 1
    d_no_index:     resb 1
    d_riprel:       resb 1
    d_sibv:         resb 1             ; raw SIB byte
    d_disp_size:    resb 1             ; 0,1,4
    d_imm_size:     resb 1             ; 0,1,2,4,8
    d_is_rel:       resb 1             ; immediate is a rel branch target
    d_imm_signed:   resb 1             ; immediate should be sign-extended
    d_byte:         resb 1             ; 1 = byte-sized operation
    d_defsize8:     resb 1             ; default operand size is 64-bit (push/pop)
    d_nosize:       resb 1             ; suppress memory size keyword (lea)
    d_op:           resb 1             ; primary opcode byte
    d_style:        resb 1             ; operand rendering style (0xff = unknown)
    d_srcsz:        resb 1             ; source size for movzx/movsx
    d_trunc:        resb 1             ; ran off the end mid-instruction
    first_printed:  resb 1             ; helper for memory-operand rendering
    d_disp:         resq 1             ; sign-extended displacement
    d_imm:          resq 1             ; immediate / relative value
    d_mnem:         resq 1             ; pointer to mnemonic string
    dstate_end:
    bytebuf:        resb 4             ; scratch for byte/number printing
    strmnem:        resb 24            ; composed mnemonic for string ops (rep + base + suffix)
    sel_off:        resq 1             ; file offset of the section to disassemble
    sel_size:       resq 1             ; its size in bytes
    sel_addr:       resq 1             ; its virtual address
    sel_name:       resq 1             ; pointer to its name

section .text
    global _start

_start:
    ; --- parse arguments: optional --json flag plus exactly one path ---
    mov r8, [rsp]              ; argc
    lea r9, [rsp + 8]         ; &argv[0]
    xor r10, r10              ; path pointer (NULL until found)
    mov byte [json_mode], 0
    mov byte [disasm_mode], 0
    mov rcx, 1               ; i = 1 (skip argv[0])
.arg_loop:
    cmp rcx, r8
    jae .args_done
    mov rsi, [r9 + rcx*8]     ; argv[i]
    lea rdi, [opt_json]
    call streq               ; al = 1 if argv[i] == "--json"
    test al, al
    jnz .arg_json
    mov rsi, [r9 + rcx*8]
    lea rdi, [opt_disasm]
    call streq
    test al, al
    jnz .arg_disasm
    mov rsi, [r9 + rcx*8]
    lea rdi, [opt_disasm_s]
    call streq
    test al, al
    jnz .arg_disasm
    mov rsi, [r9 + rcx*8]
    test r10, r10            ; otherwise it's the path (only one allowed)
    jnz .usage
    mov r10, rsi
    jmp .arg_next
.arg_json:
    mov byte [json_mode], 1
    jmp .arg_next
.arg_disasm:
    mov byte [disasm_mode], 1
.arg_next:
    inc rcx
    jmp .arg_loop
.args_done:
    test r10, r10            ; a path is required
    jz .usage

    mov rdi, r10             ; open(path, O_RDONLY)
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

    mov eax, dword [ehdr]      ; validate magic
    cmp eax, dword [elf_magic]
    jne .invalid

    cmp qword [nread], EHDR_SIZE
    jl .truncated

    cmp byte [disasm_mode], 0
    jne .emit_disasm
    cmp byte [json_mode], 0
    jne .emit_json
    call print_header
    call print_program_headers ; reads segments via fd in r12
    call print_section_headers ; reads sections via fd in r12
    call validate_structure    ; sanity-check offsets, counts [issues]
    call check_security        ; segment perms + stack exec, counts [warnings]
    call analyze_dynamic       ; needed libraries + imported symbols
    call check_hardening       ; exploit-mitigation posture (checksec-style)
    jmp .after_output
.emit_json:
    call print_json            ; emits everything + counts [issues]
    jmp .after_output
.emit_disasm:
    call disassemble           ; disassemble .text; leaves [issues] at 0
.after_output:
    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall
    xor edi, edi            ; exit 0 if no structural issues...
    cmp qword [issues], 0
    je .exit
    mov edi, 2              ; ...else exit 2
    jmp .exit

.invalid:
    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall
    lea rsi, [invalid_msg]
    mov rdx, invalid_len
    call print_stderr
    mov edi, 1
    jmp .exit

.truncated:
    mov rdi, r12            ; close fd
    mov rax, SYS_CLOSE
    syscall
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

; load_shstrtab - read the section-name string table (section shstrndx) into
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

    ; --- e_ehsize == 64 ---
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
    call print_imports
.ad_ret:
    ret

; ---------------------------------------------------------------------------
; check_hardening - report exploit-mitigation posture (checksec-style):
;   RELRO, stack canary, NX, PIE, RPATH/RUNPATH and Fortify.
;   Gathers facts into hd_* then prints them.  Uses VP/vprint/vdec so it also
;   populates the hd_* fields silently for the JSON path.  fd in r12.
; ---------------------------------------------------------------------------
check_hardening:
    VP hd_title
    call hd_scan_phdrs         ; -> hd_interp, hd_stack, hd_relro_seg
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
    jmp .h_rpath
.h_pie_no:
    VP hd_disabled
    jmp .h_rpath
.h_pie_dso:
    VP hd_dso
    jmp .h_rpath
.h_pie_na:
    VP hd_na
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
; print_json - emit the whole analysis as a single-line JSON object.
; Minified on purpose (pipe through `jq` for pretty-printing).
; ---------------------------------------------------------------------------
print_json:
    PRINT j_lbrace
    call json_header
    PRINT j_comma
    call json_phdrs
    PRINT j_comma
    call json_shdrs
    PRINT j_comma
    call json_validation
    PRINT j_comma
    call json_security
    PRINT j_comma
    call json_dynamic
    PRINT j_comma
    call json_hardening
    PRINT j_rbrace
    PRINT nl
    ret

; json_header - "header":{ ...fields... }
json_header:
    PRINT jk_header
    PRINT j_lbrace

    PRINT jk_class
    movzx eax, byte [ehdr + EI_CLASS]
    call class_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_data
    movzx eax, byte [ehdr + EI_DATA]
    call data_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_osabi
    movzx eax, byte [ehdr + EI_OSABI]
    call osabi_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_type
    movzx eax, word [ehdr + E_TYPE]
    call type_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_machine
    movzx eax, word [ehdr + E_MACHINE]
    call machine_name
    mov rsi, rax
    call jname
    PRINT j_comma

    PRINT jk_entry
    mov rax, [ehdr + E_ENTRY]
    call jhex
    PRINT j_comma

    PRINT jk_phoff
    mov rax, [ehdr + E_PHOFF]
    call print_dec
    PRINT j_comma

    PRINT jk_shoff
    mov rax, [ehdr + E_SHOFF]
    call print_dec
    PRINT j_comma

    PRINT jk_flags
    mov eax, dword [ehdr + E_FLAGS]
    call jhex
    PRINT j_comma

    PRINT jk_ehsize
    movzx eax, word [ehdr + E_EHSIZE]
    call print_dec
    PRINT j_comma

    PRINT jk_phentsize
    movzx eax, word [ehdr + E_PHENTSIZE]
    call print_dec
    PRINT j_comma

    PRINT jk_phnum
    movzx eax, word [ehdr + E_PHNUM]
    call print_dec
    PRINT j_comma

    PRINT jk_shentsize
    movzx eax, word [ehdr + E_SHENTSIZE]
    call print_dec
    PRINT j_comma

    PRINT jk_shnum
    movzx eax, word [ehdr + E_SHNUM]
    call print_dec
    PRINT j_comma

    PRINT jk_shstrndx
    movzx eax, word [ehdr + E_SHSTRNDX]
    call print_dec

    PRINT j_rbrace
    ret

; json_phdrs - "program_headers":[ {..}, {..} ]
json_phdrs:
    PRINT jk_phdrs
    PRINT j_lbrack
    movzx r14d, word [ehdr + E_PHNUM]
    xor r13, r13
.jp_loop:
    cmp r13, r14
    jae .jp_done
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
    jl .jp_done
    test r13, r13
    jz .jp_nocomma
    PRINT j_comma
.jp_nocomma:
    call json_one_phdr
    inc r13
    jmp .jp_loop
.jp_done:
    PRINT j_rbrack
    ret

json_one_phdr:
    PRINT j_lbrace
    PRINT jk_index
    mov rax, r13
    call print_dec
    PRINT j_comma
    PRINT jk_type
    mov eax, dword [phdr + P_TYPE]
    call phdr_type_name
    mov rsi, rax
    call jname
    PRINT j_comma
    PRINT jk_flags
    mov eax, dword [phdr + P_FLAGS]
    call build_flags
    lea rsi, [flagbuf]
    call jname
    PRINT j_comma
    PRINT jk_offset
    mov rax, [phdr + P_OFFSET]
    call jhex
    PRINT j_comma
    PRINT jk_vaddr
    mov rax, [phdr + P_VADDR]
    call jhex
    PRINT j_comma
    PRINT jk_filesz
    mov rax, [phdr + P_FILESZ]
    call jhex
    PRINT j_comma
    PRINT jk_memsz
    mov rax, [phdr + P_MEMSZ]
    call jhex
    PRINT j_comma
    PRINT jk_align
    mov rax, [phdr + P_ALIGN]
    call jhex
    PRINT j_rbrace
    ret

; json_shdrs - "section_headers":[ {..}, {..} ]
json_shdrs:
    PRINT jk_shdrs
    PRINT j_lbrack
    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .js_done
    call load_shstrtab
    xor r13, r13
.js_loop:
    cmp r13, r14
    jae .js_done
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
    jl .js_done
    test r13, r13
    jz .js_nocomma
    PRINT j_comma
.js_nocomma:
    call json_one_shdr
    inc r13
    jmp .js_loop
.js_done:
    PRINT j_rbrack
    ret

json_one_shdr:
    PRINT j_lbrace
    PRINT jk_index
    mov rax, r13
    call print_dec
    PRINT j_comma
    PRINT jk_name
    call section_name_ptr       ; rsi -> name
    call jstr                   ; escaped (name comes from the file)
    PRINT j_comma
    PRINT jk_type
    mov eax, dword [shdr + SH_TYPE]
    call shdr_type_name
    mov rsi, rax
    call jname
    PRINT j_comma
    PRINT jk_flags
    mov rax, [shdr + SH_FLAGS]
    call build_sh_flags
    lea rsi, [shflagbuf]
    call jname
    PRINT j_comma
    PRINT jk_addr
    mov rax, [shdr + SH_ADDR]
    call jhex
    PRINT j_comma
    PRINT jk_offset
    mov rax, [shdr + SH_OFFSET]
    call jhex
    PRINT j_comma
    PRINT jk_size
    mov rax, [shdr + SH_SIZE]
    call jhex
    PRINT j_comma
    PRINT jk_addralign
    mov rax, [shdr + SH_ADDRALIGN]
    call jhex
    PRINT j_rbrace
    ret

; json_validation - "validation":{"issues":N,"valid":bool}
; Runs validate_structure silently to count issues.
json_validation:
    PRINT jk_validation
    PRINT j_lbrace
    mov byte [silent], 1
    call validate_structure
    mov byte [silent], 0
    PRINT jk_issues
    mov rax, [issues]
    call print_dec
    PRINT j_comma
    PRINT jk_valid
    cmp qword [issues], 0
    jne .jv_invalid
    PRINT j_true
    jmp .jv_close
.jv_invalid:
    PRINT j_false
.jv_close:
    PRINT j_rbrace
    ret

; json_security - "security":{"gnu_stack":"...","executable_stack":bool,
;                 "wx_segments":N,"wx_sections":N,"entry_in_exec":bool,
;                 "has_section_headers":bool,"warnings":N}
; Runs check_security silently to populate the counters.
json_security:
    PRINT jk_security
    PRINT j_lbrace
    mov byte [silent], 1
    call check_security
    mov byte [silent], 0
    PRINT jk_gnustack
    cmp byte [sec_stack], 2
    je .js_exec
    cmp byte [sec_stack], 1
    je .js_noexec
    lea rsi, [jv_st_absent]
    jmp .js_stname
.js_noexec:
    lea rsi, [jv_st_noexec]
    jmp .js_stname
.js_exec:
    lea rsi, [jv_st_exec]
.js_stname:
    call jname
    PRINT j_comma
    PRINT jk_execstack
    cmp byte [sec_stack], 2
    jne .js_nx
    PRINT j_true
    jmp .js_wx
.js_nx:
    PRINT j_false
.js_wx:
    PRINT j_comma
    PRINT jk_wxseg
    mov rax, [sec_wx]
    call print_dec
    PRINT j_comma
    PRINT jk_wxsect
    mov rax, [sec_wxsect]
    call print_dec
    PRINT j_comma
    PRINT jk_entryok
    ; entry_in_exec: true if entry==0 (no code address) or it lies in exec seg
    cmp qword [ehdr + E_ENTRY], 0
    je .js_entry_true
    cmp byte [sec_entry_ok], 1
    je .js_entry_true
    PRINT j_false
    jmp .js_shdr
.js_entry_true:
    PRINT j_true
.js_shdr:
    PRINT j_comma
    PRINT jk_hasshdr
    cmp word [ehdr + E_SHNUM], 0
    je .js_noshdr
    PRINT j_true
    jmp .js_warn
.js_noshdr:
    PRINT j_false
.js_warn:
    PRINT j_comma
    PRINT jk_warnings
    mov rax, [warnings]
    call print_dec
    PRINT j_rbrace
    ret

; json_dynamic - "dynamic":{"static":bool,"needed":[..],"imports":[..]}
json_dynamic:
    PRINT jk_dynamic
    PRINT j_lbrace
    PRINT jk_static
    cmp word [ehdr + E_SHNUM], 0
    je .jd_static
    mov eax, 6                  ; SHT_DYNAMIC
    call find_section
    cmp rax, -1
    jne .jd_dynamic
.jd_static:
    PRINT j_true
    PRINT j_comma
    PRINT jk_needed
    PRINT j_lbrack
    PRINT j_rbrack
    PRINT j_comma
    PRINT jk_imports
    PRINT j_lbrack
    PRINT j_rbrack
    PRINT j_rbrace
    ret
.jd_dynamic:
    PRINT j_false
    mov rax, [shdr + SH_OFFSET]
    mov [dyn_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [dyn_size], rax
    mov eax, dword [shdr + SH_LINK]
    mov [dyn_link], eax
    mov eax, dword [dyn_link]
    call load_dynstr
    PRINT j_comma
    PRINT jk_needed
    PRINT j_lbrack
    call json_needed_arr
    PRINT j_rbrack
    PRINT j_comma
    PRINT jk_imports
    PRINT j_lbrack
    mov eax, 11                 ; SHT_DYNSYM
    call find_section
    cmp rax, -1
    je .jd_noimp
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
    call json_imports_arr
.jd_noimp:
    PRINT j_rbrack
    PRINT j_rbrace
    ret

; json_needed_arr - emit comma-separated JSON strings for DT_NEEDED libs
json_needed_arr:
    mov r14, [dyn_size]
    shr r14, 4
    xor r13, r13
    xor rbx, rbx
.jn_loop:
    cmp r13, r14
    jae .jn_done
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
    jl .jn_done
    mov rax, [dynent]
    test rax, rax
    jz .jn_done
    cmp rax, 1                  ; DT_NEEDED
    jne .jn_next
    test rbx, rbx
    jz .jn_nocomma
    PRINT j_comma
.jn_nocomma:
    mov rax, [dynent + 8]
    call dynstr_name_ptr
    call jstr
    inc rbx
.jn_next:
    inc r13
    jmp .jn_loop
.jn_done:
    ret

; json_imports_arr - emit comma-separated JSON strings for imported symbols
json_imports_arr:
    mov rcx, [dsym_ent]
    test rcx, rcx
    jz .ji_done
    mov rax, [dsym_size]
    xor rdx, rdx
    div rcx
    mov r14, rax
    xor r13, r13
    xor rbx, rbx
.ji_loop:
    cmp r13, r14
    jae .ji_done
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
    jl .ji_done
    movzx eax, word [syment + 6]
    test eax, eax
    jnz .ji_next
    mov eax, dword [syment]
    test eax, eax
    jz .ji_next
    test rbx, rbx
    jz .ji_nocomma
    PRINT j_comma
.ji_nocomma:
    mov eax, dword [syment]
    call dynstr_name_ptr
    call jstr
    inc rbx
.ji_next:
    inc r13
    jmp .ji_loop
.ji_done:
    ret

; json_hardening - "hardening":{"relro":..,"stack_canary":bool,"nx":..,
;                 "pie":..,"rpath":str|null,"runpath":str|null,"fortify":N}
; Runs check_hardening silently to populate the hd_* fields.
json_hardening:
    PRINT jk_hardening
    PRINT j_lbrace
    mov byte [silent], 1
    call check_hardening
    mov byte [silent], 0
    ; --- relro ---
    PRINT jk_relro
    cmp byte [hd_relro_seg], 0
    je .jh_relro_none
    cmp byte [hd_bindnow], 0
    jne .jh_relro_full
    lea rsi, [jv_partial]
    jmp .jh_relro_emit
.jh_relro_full:
    lea rsi, [jv_full]
    jmp .jh_relro_emit
.jh_relro_none:
    lea rsi, [jv_none]
.jh_relro_emit:
    call jname
    PRINT j_comma
    ; --- stack_canary ---
    PRINT jk_canary
    cmp byte [hd_canary], 0
    jne .jh_can_true
    PRINT j_false
    jmp .jh_nx
.jh_can_true:
    PRINT j_true
.jh_nx:
    PRINT j_comma
    ; --- nx ---
    PRINT jk_nx
    cmp byte [hd_stack], 2
    je .jh_nx_dis
    cmp byte [hd_stack], 0
    je .jh_nx_unk
    lea rsi, [jv_enabled]
    jmp .jh_nx_emit
.jh_nx_dis:
    lea rsi, [jv_disabled]
    jmp .jh_nx_emit
.jh_nx_unk:
    lea rsi, [jv_unknown]
.jh_nx_emit:
    call jname
    PRINT j_comma
    ; --- pie ---
    PRINT jk_pie
    movzx eax, word [ehdr + E_TYPE]
    cmp eax, ET_EXEC
    je .jh_pie_dis
    cmp eax, ET_DYN
    jne .jh_pie_na
    cmp byte [hd_interp], 0
    je .jh_pie_dso
    lea rsi, [jv_enabled]
    jmp .jh_pie_emit
.jh_pie_dis:
    lea rsi, [jv_disabled]
    jmp .jh_pie_emit
.jh_pie_dso:
    lea rsi, [jv_dso]
    jmp .jh_pie_emit
.jh_pie_na:
    lea rsi, [jv_na]
.jh_pie_emit:
    call jname
    PRINT j_comma
    ; --- rpath ---
    PRINT jk_rpath
    cmp qword [hd_rpath_off], -1
    je .jh_rpath_null
    mov rax, [hd_rpath_off]
    call dynstr_name_ptr
    call jstr
    jmp .jh_runpath
.jh_rpath_null:
    PRINT j_null
.jh_runpath:
    PRINT j_comma
    ; --- runpath ---
    PRINT jk_runpath
    cmp qword [hd_runpath_off], -1
    je .jh_runpath_null
    mov rax, [hd_runpath_off]
    call dynstr_name_ptr
    call jstr
    jmp .jh_fortify
.jh_runpath_null:
    PRINT j_null
.jh_fortify:
    PRINT j_comma
    ; --- fortify ---
    PRINT jk_fortify
    mov rax, [hd_fortify]
    call print_dec
    PRINT j_rbrace
    ret

; ---------------------------------------------------------------------------
; jname - print rsi as a JSON string, no escaping (safe enum/flag text only)
; ---------------------------------------------------------------------------
jname:                     ; in: rsi = cstr
    push rsi
    PRINT j_quote
    pop rsi
    call print_cstr
    PRINT j_quote
    ret

; ---------------------------------------------------------------------------
; jstr - print rsi as a JSON string, escaping \" \\ and control bytes
; ---------------------------------------------------------------------------
jstr:                      ; in: rsi = cstr
    push rsi
    PRINT j_quote
    pop rsi
    call json_escape
    PRINT j_quote
    ret

; ---------------------------------------------------------------------------
; jhex - print rax as a JSON string holding its "0x.." hex form
; ---------------------------------------------------------------------------
jhex:                      ; in: rax = value
    push rax
    PRINT j_quote
    pop rax
    call print_hex
    PRINT j_quote
    ret

; ---------------------------------------------------------------------------
; json_escape - print NUL-terminated string (rsi), escaping JSON specials.
; ---------------------------------------------------------------------------
json_escape:               ; in: rsi = cstr
    push rbx
    mov rbx, rsi
.je_loop:
    movzx eax, byte [rbx]
    test al, al
    jz .je_done
    cmp al, 34                 ; "
    je .je_quote
    cmp al, 92                 ; backslash
    je .je_bslash
    cmp al, 0x20               ; control char
    jb .je_ctrl
    mov [jbuf], al             ; ordinary byte
    lea rsi, [jbuf]
    mov rdx, 1
    call print_str
    jmp .je_next
.je_quote:
    PRINT esc_quote
    jmp .je_next
.je_bslash:
    PRINT esc_bslash
    jmp .je_next
.je_ctrl:
    PRINT esc_u00              ; emit \u00 then two hex digits
    movzx eax, byte [rbx]
    mov edx, eax
    shr edx, 4
    and edx, 0xf
    mov al, dl
    call nibble_hex
    mov [jbuf], al
    movzx edx, byte [rbx]
    and edx, 0xf
    mov al, dl
    call nibble_hex
    mov [jbuf + 1], al
    lea rsi, [jbuf]
    mov rdx, 2
    call print_str
.je_next:
    inc rbx
    jmp .je_loop
.je_done:
    pop rbx
    ret

; nibble_hex - low nibble of al -> ascii hex char in al
nibble_hex:
    and al, 0xf
    cmp al, 10
    jb .nh_digit
    add al, 'a' - 10
    ret
.nh_digit:
    add al, '0'
    ret

; ===========================================================================
; Disassembler (x86-64, common integer subset).  Unknown bytes fall back to
; a single ".byte 0x.." so decoding always makes forward progress.
; ===========================================================================

; disassemble - locate .text (PROGBITS + EXECINSTR), load it, decode & print.
disassemble:
    mov qword [issues], 0
    mov qword [sel_off], -1
    mov qword [text_trunc], 0
    movzx r14d, word [ehdr + E_SHNUM]
    test r14, r14
    jz .none
    call load_shstrtab
    xor r13, r13
.find_loop:
    cmp r13, r14
    jae .find_done
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
    jl .find_done
    mov eax, dword [shdr + SH_TYPE]     ; PROGBITS?
    cmp eax, 1
    jne .next
    test byte [shdr + SH_FLAGS], 0x4    ; SHF_EXECINSTR?
    jz .next
    call section_name_ptr               ; rsi -> name
    push rsi
    lea rdi, [name_text]
    call streq
    pop rsi
    test al, al
    jnz .pick
    cmp qword [sel_off], -1             ; else remember first exec section
    jne .next
    call .save_sel
    jmp .next
.pick:
    call .save_sel
    jmp .find_done
.next:
    inc r13
    jmp .find_loop
.save_sel:
    mov rax, [shdr + SH_OFFSET]
    mov [sel_off], rax
    mov rax, [shdr + SH_SIZE]
    mov [sel_size], rax
    mov rax, [shdr + SH_ADDR]
    mov [sel_addr], rax
    mov [sel_name], rsi
    ret
.find_done:
    cmp qword [sel_off], -1
    je .none
    mov rax, [sel_size]                 ; clamp to TEXT_CAP
    cmp rax, TEXT_CAP
    jbe .szok
    mov rax, TEXT_CAP
    mov qword [text_trunc], 1
.szok:
    mov [text_len], rax
    mov rax, [sel_addr]
    mov [text_vaddr], rax
    mov rdi, r12                        ; read section bytes into textbuf
    mov rsi, [sel_off]
    xor edx, edx
    mov rax, SYS_LSEEK
    syscall
    mov rdi, r12
    lea rsi, [textbuf]
    mov rdx, [text_len]
    mov rax, SYS_READ
    syscall
    test rax, rax
    js .none
    mov [text_len], rax
    PRINT dis_title                     ; header line
    mov rsi, [sel_name]
    call print_cstr
    PRINT dis_colon_nl
    lea rax, [textbuf]                  ; set up decode loop
    mov [d_cur], rax
    add rax, [text_len]
    mov [d_end], rax
.dloop:
    mov rax, [d_cur]
    cmp rax, [d_end]
    jae .dend
    lea rdx, [textbuf]                  ; vaddr of this instruction
    sub rax, rdx
    add rax, [text_vaddr]
    mov [d_vaddr], rax
    call decode_one
    jmp .dloop
.dend:
    cmp qword [text_trunc], 0
    je .ret
    PRINT dis_trunc_note
.ret:
    ret
.none:
    lea rsi, [dis_nosect]
    mov rdx, dis_nosect_len
    call print_stderr
    ret

; --- byte stream access over textbuf (cursor in [d_cur], limit [d_end]) ---
peek8:                         ; out: al = byte (0 at end, sets d_trunc)
    mov rsi, [d_cur]
    cmp rsi, [d_end]
    jb .ok
    mov byte [d_trunc], 1
    xor eax, eax
    ret
.ok:
    movzx eax, byte [rsi]
    ret

adv8:
    inc qword [d_cur]
    ret

fetch8:                        ; out: al = next byte, cursor advanced
    call peek8
    push rax
    call adv8
    pop rax
    ret

; read_bytes_le - read cl (1..8) bytes little-endian; out rax zero-extended.
read_bytes_le:
    push rbx
    push r12
    xor eax, eax
    xor r12d, r12d             ; shift amount
    movzx ebx, cl              ; remaining count
.loop:
    test ebx, ebx
    jz .done
    push rax
    call fetch8
    movzx edx, al
    pop rax
    mov cl, r12b
    shl rdx, cl
    or rax, rdx
    add r12d, 8
    dec ebx
    jmp .loop
.done:
    pop r12
    pop rbx
    ret

; sign_extend - in: rax value, cl = width (1,2,4) -> rax sign-extended.
sign_extend:
    cmp cl, 1
    je .s1
    cmp cl, 2
    je .s2
    cmp cl, 4
    je .s4
    ret
.s1:
    movsx rax, al
    ret
.s2:
    movsx rax, ax
    ret
.s4:
    movsxd rax, eax
    ret

set_imm_vsize:                 ; imm width: 2 with 0x66, else 4
    cmp byte [d_opsize], 1
    je .w
    mov byte [d_imm_size], 4
    ret
.w:
    mov byte [d_imm_size], 2
    ret

read_disp:
    movzx ecx, byte [d_disp_size]
    test ecx, ecx
    jz .none
    call read_bytes_le
    movzx ecx, byte [d_disp_size]
    call sign_extend
    mov [d_disp], rax
.none:
    ret

read_imm:
    movzx ecx, byte [d_imm_size]
    test ecx, ecx
    jz .none
    call read_bytes_le
    cmp byte [d_imm_signed], 1
    jne .store
    movzx ecx, byte [d_imm_size]
    call sign_extend
.store:
    mov [d_imm], rax
.none:
    ret

set_disp_by_mod:
    cmp byte [d_mod], 1
    je .d8
    cmp byte [d_mod], 2
    je .d32
    mov byte [d_disp_size], 0
    ret
.d8:
    mov byte [d_disp_size], 1
    ret
.d32:
    mov byte [d_disp_size], 4
    ret

; parse_modrm - consume ModR/M (+ SIB) and set the operand fields.
parse_modrm:
    call fetch8
    mov [d_modrm], al
    mov cl, al                 ; mod
    shr cl, 6
    mov [d_mod], cl
    mov dl, al                 ; reg + REX.R
    shr dl, 3
    and dl, 7
    test byte [d_rex], 4
    jz .r1
    or dl, 8
.r1:
    mov [d_reg], dl
    mov bl, al                 ; rm low 3 bits
    and bl, 7
    cmp byte [d_mod], 3
    jne .mem
    mov dl, bl                 ; register-direct rm
    test byte [d_rex], 1
    jz .r2
    or dl, 8
.r2:
    mov [d_rm], dl
    mov byte [d_mem], 0
    ret
.mem:
    mov byte [d_mem], 1
    cmp bl, 4
    je .sib
    cmp byte [d_mod], 0
    jne .base
    cmp bl, 5
    jne .base
    mov byte [d_riprel], 1     ; RIP-relative
    mov byte [d_disp_size], 4
    ret
.base:
    mov dl, bl
    test byte [d_rex], 1
    jz .r3
    or dl, 8
.r3:
    mov [d_base], dl
    mov byte [d_no_index], 1
    call set_disp_by_mod
    ret
.sib:
    call fetch8
    mov [d_sibv], al
    mov cl, al                 ; scale
    shr cl, 6
    mov [d_scale], cl
    mov dl, al                 ; index
    shr dl, 3
    and dl, 7
    cmp dl, 4
    jne .have_index
    test byte [d_rex], 2
    jnz .have_index
    mov byte [d_no_index], 1
    jmp .sbase
.have_index:
    test byte [d_rex], 2
    jz .hi
    or dl, 8
.hi:
    mov [d_index], dl
.sbase:
    mov al, [d_sibv]
    and al, 7
    cmp al, 5
    jne .sreg
    cmp byte [d_mod], 0
    jne .sreg5
    mov byte [d_no_base], 1    ; mod==0, base==101 -> disp32 only
    mov byte [d_disp_size], 4
    ret
.sreg5:
    mov dl, 5
    test byte [d_rex], 1
    jz .sr5
    or dl, 8
.sr5:
    mov [d_base], dl
    call set_disp_by_mod
    ret
.sreg:
    mov dl, al
    test byte [d_rex], 1
    jz .sr
    or dl, 8
.sr:
    mov [d_base], dl
    call set_disp_by_mod
    ret

reset_decode_state:
    lea rdi, [dstate]
    mov ecx, dstate_end - dstate
    xor eax, eax
    rep stosb
    ret

; cur_opnd_size - out: cl = operand size in bytes (1,2,4,8)
cur_opnd_size:
    cmp byte [d_byte], 1
    je .s1
    test byte [d_rex], 8       ; REX.W
    jnz .s8
    cmp byte [d_opsize], 1
    je .s2
    cmp byte [d_defsize8], 1
    je .s8
    mov cl, 4
    ret
.s8:
    mov cl, 8
    ret
.s2:
    mov cl, 2
    ret
.s1:
    mov cl, 1
    ret

; emit_reg - al = index (0-15), cl = size (1,2,4,8); prints register name
emit_reg:
    push rbx
    movzx ebx, al
    cmp cl, 8
    je .q
    cmp cl, 4
    je .d
    cmp cl, 2
    je .w
    test byte [d_hasrex], 1    ; byte register
    jnz .brex
    cmp ebx, 4
    jb .brex
    cmp ebx, 8
    jae .brex
    lea rax, [regs8h]
    mov rsi, [rax + rbx*8]
    jmp .out
.brex:
    lea rax, [regs8]
    mov rsi, [rax + rbx*8]
    jmp .out
.q:
    lea rax, [regs64]
    mov rsi, [rax + rbx*8]
    jmp .out
.d:
    lea rax, [regs32]
    mov rsi, [rax + rbx*8]
    jmp .out
.w:
    lea rax, [regs16]
    mov rsi, [rax + rbx*8]
.out:
    call print_cstr
    pop rbx
    ret

; emit_disp_signed - print "+0x.." or "-0x.." for [d_disp]
emit_disp_signed:
    mov rax, [d_disp]
    test rax, rax
    js .neg
    PRINT dis_plus
    mov rax, [d_disp]
    call print_hex
    ret
.neg:
    PRINT dis_minus
    mov rax, [d_disp]
    neg rax
    call print_hex
    ret

; emit_rm - cl = size; print the ModR/M r/m operand (register or memory)
emit_rm:
    cmp byte [d_mem], 0
    jne .mem
    mov al, [d_rm]
    jmp emit_reg               ; tail call, cl already set
.mem:
    cmp byte [d_nosize], 1
    je .nokw
    push rcx                   ; size keyword
    movzx eax, cl
    cmp al, 1
    je .k0
    cmp al, 2
    je .k1
    cmp al, 4
    je .k2
    mov edx, 3
    jmp .kk
.k0:
    xor edx, edx
    jmp .kk
.k1:
    mov edx, 1
    jmp .kk
.k2:
    mov edx, 2
.kk:
    lea rax, [sz_tbl]
    mov rsi, [rax + rdx*8]
    call print_cstr
    pop rcx
.nokw:
    PRINT dis_lbr
    cmp byte [d_riprel], 1
    jne .notrip
    PRINT dis_rip
    call emit_disp_signed
    jmp .close
.notrip:
    mov byte [first_printed], 0
    cmp byte [d_no_base], 1
    je .aftbase
    mov al, [d_base]
    push rcx
    mov cl, 8
    call emit_reg
    pop rcx
    mov byte [first_printed], 1
.aftbase:
    cmp byte [d_no_index], 1
    je .aftindex
    cmp byte [first_printed], 1
    jne .noplus
    PRINT dis_plus
.noplus:
    mov al, [d_index]
    push rcx
    mov cl, 8
    call emit_reg
    pop rcx
    PRINT dis_star
    movzx ecx, byte [d_scale]  ; scale = 1 << exponent
    mov eax, 1
    shl eax, cl
    mov rax, rax
    push rcx
    call print_dec
    pop rcx
    mov byte [first_printed], 1
.aftindex:
    movzx eax, byte [d_disp_size]
    test eax, eax
    jz .close
    cmp byte [first_printed], 1
    jne .displead
    call emit_disp_signed
    jmp .close
.displead:
    mov rax, [d_disp]
    call print_hex
.close:
    PRINT dis_rbr
    ret

emit_imm:
    mov rax, [d_imm]
    call print_hex
    ret

; print_byte_hex - al -> two lowercase hex chars on stdout
print_byte_hex:
    push rax
    mov dl, al
    shr dl, 4
    mov al, dl
    call nibble_hex
    mov [bytebuf], al
    pop rax
    mov dl, al
    and dl, 0xf
    mov al, dl
    call nibble_hex
    mov [bytebuf + 1], al
    lea rsi, [bytebuf]
    mov rdx, 2
    call print_str
    ret

; render_operands - print operands according to [d_style]
render_operands:
    movzx eax, byte [d_style]
    cmp eax, ST_RM_REG
    je .rm_reg
    cmp eax, ST_REG_RM
    je .reg_rm
    cmp eax, ST_RM_IMM
    je .rm_imm
    cmp eax, ST_RM
    je .rm
    cmp eax, ST_REG_IMM
    je .reg_imm
    cmp eax, ST_OREG
    je .oreg
    cmp eax, ST_ACC_IMM
    je .acc_imm
    cmp eax, ST_REL
    je .rel
    cmp eax, ST_IMM
    je .imm
    cmp eax, ST_RM_1
    je .rm_1
    cmp eax, ST_RM_CL
    je .rm_cl
    cmp eax, ST_REG_RM_B
    je .reg_rm_b
    cmp eax, ST_REG_RM_IMM
    je .reg_rm_imm
    ret
.rm_reg:
    call cur_opnd_size
    push rcx
    call emit_rm
    PRINT dis_comma
    pop rcx
    mov al, [d_reg]
    call emit_reg
    ret
.reg_rm:
    call cur_opnd_size
    push rcx
    mov al, [d_reg]
    call emit_reg
    PRINT dis_comma
    pop rcx
    call emit_rm
    ret
.rm_imm:
    call cur_opnd_size
    call emit_rm
    PRINT dis_comma
    call emit_imm
    ret
.rm:
    call cur_opnd_size
    call emit_rm
    ret
.reg_imm:
    call cur_opnd_size
    mov al, [d_reg]
    call emit_reg
    PRINT dis_comma
    call emit_imm
    ret
.oreg:
    call cur_opnd_size
    mov al, [d_reg]
    call emit_reg
    ret
.acc_imm:
    call cur_opnd_size
    xor al, al
    call emit_reg
    PRINT dis_comma
    call emit_imm
    ret
.rel:
    mov rax, [d_cur]
    sub rax, [d_start]
    add rax, [d_vaddr]
    add rax, [d_imm]
    call print_hex
    ret
.imm:
    call emit_imm
    ret
.rm_1:
    call cur_opnd_size
    call emit_rm
    PRINT dis_comma
    PRINT dis_one
    ret
.rm_cl:
    call cur_opnd_size
    call emit_rm
    PRINT dis_comma
    PRINT dis_cl
    ret
.reg_rm_b:
    call cur_opnd_size
    push rcx
    mov al, [d_reg]
    call emit_reg
    PRINT dis_comma
    pop rcx
    movzx ecx, byte [d_srcsz]
    call emit_rm
    ret
.reg_rm_imm:
    call cur_opnd_size
    push rcx
    mov al, [d_reg]
    call emit_reg
    PRINT dis_comma
    mov rcx, [rsp]
    call emit_rm
    PRINT dis_comma
    pop rcx
    call emit_imm
    ret

; print_insn - render address, raw bytes and decoded instruction
print_insn:
    PRINT two_spaces
    mov rax, [d_vaddr]
    call print_hex
    PRINT dis_colon
    PRINT dis_space
    mov rbx, [d_start]
.bytes:
    cmp rbx, [d_cur]
    jae .bytes_done
    movzx eax, byte [rbx]
    push rbx
    call print_byte_hex
    PRINT dis_space
    pop rbx
    inc rbx
    jmp .bytes
.bytes_done:
    mov rax, [d_cur]           ; pad bytes column to 30
    sub rax, [d_start]
    imul rax, 3
    mov rdx, 30
    sub rdx, rax
    jle .mnem
    lea rsi, [dis_pad]
    call print_str
.mnem:
    mov rsi, [d_mnem]
    test rsi, rsi
    jz .done
    mov ecx, 7
    call print_cstr_pad
    call render_operands
.done:
    PRINT nl
    ret

; print_byte_insn - fallback line ".byte 0x.." for one unknown byte
print_byte_insn:
    PRINT two_spaces
    mov rax, [d_vaddr]
    call print_hex
    PRINT dis_colon
    PRINT dis_space
    mov rbx, [d_start]
    movzx eax, byte [rbx]
    call print_byte_hex
    PRINT dis_space
    mov rdx, 30 - 3
    lea rsi, [dis_pad]
    call print_str
    PRINT dis_byte_db
    PRINT dis_0x
    mov rbx, [d_start]
    movzx eax, byte [rbx]
    call print_byte_hex
    PRINT nl
    ret

; decode_one - decode and print a single instruction; out rax = length.
decode_one:
    call reset_decode_state
    mov rax, [d_cur]
    mov [d_start], rax
.pfx:
    call peek8
    cmp al, 0x66
    je .p66
    cmp al, 0x67
    je .p67
    cmp al, 0xf0
    je .pf0
    cmp al, 0xf2
    je .pf2
    cmp al, 0xf3
    je .pf3
    cmp al, 0x2e
    je .pseg
    cmp al, 0x36
    je .pseg
    cmp al, 0x3e
    je .pseg
    cmp al, 0x26
    je .pseg
    cmp al, 0x64
    je .pseg
    cmp al, 0x65
    je .pseg
    jmp .pfx_done
.p66:
    mov byte [d_opsize], 1
    call adv8
    jmp .pfx
.p67:
    mov byte [d_addrsz], 1
    call adv8
    jmp .pfx
.pf0:
    mov byte [d_lock], 1
    call adv8
    jmp .pfx
.pf2:
    mov byte [d_repne], 1
    call adv8
    jmp .pfx
.pf3:
    mov byte [d_rep], 1
    call adv8
    jmp .pfx
.pseg:
    mov [d_seg], al
    call adv8
    jmp .pfx
.pfx_done:
    call peek8                 ; REX?
    mov dl, al
    and dl, 0xf0
    cmp dl, 0x40
    jne .norex
    mov [d_rex], al
    mov byte [d_hasrex], 1
    call adv8
.norex:
    call fetch8                ; opcode
    cmp al, 0x0f
    je .two
    mov [d_op], al
    call decode_one_byte
    jmp .finish
.two:
    call fetch8
    call decode_two_byte
.finish:
    cmp byte [d_trunc], 1
    je .as_byte
    cmp byte [d_style], 0xff
    je .as_byte
    call print_insn
    jmp .ret
.as_byte:
    mov rax, [d_start]
    inc rax
    mov [d_cur], rax
    call print_byte_insn
.ret:
    mov rax, [d_cur]
    sub rax, [d_start]
    ret

; decode_one_byte - in: al = opcode (also saved in [d_op]).
decode_one_byte:
    ; --- arithmetic block 0x00..0x3F (columns 0-5 of each group of 8) ---
    cmp al, 0x40
    jae .not_arith
    mov bl, al
    and bl, 7
    cmp bl, 6
    jae .not_arith
    mov cl, al
    shr cl, 3
    movzx ecx, cl
    lea rax, [grp_arith]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    cmp bl, 0
    je .ar0
    cmp bl, 1
    je .ar1
    cmp bl, 2
    je .ar2
    cmp bl, 3
    je .ar3
    cmp bl, 4
    je .ar4
    mov byte [d_style], ST_ACC_IMM   ; col 5: eAX, imm
    call set_imm_vsize
    call read_imm
    ret
.ar4:
    mov byte [d_byte], 1             ; col 4: AL, imm8
    mov byte [d_style], ST_ACC_IMM
    mov byte [d_imm_size], 1
    call read_imm
    ret
.ar0:
    mov byte [d_byte], 1
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.ar1:
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.ar2:
    mov byte [d_byte], 1
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.ar3:
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.not_arith:
    ; --- push/pop r64 (0x50..0x5F) ---
    cmp al, 0x50
    jb .c63
    cmp al, 0x5f
    ja .c63
    mov bl, al
    and bl, 7
    test byte [d_rex], 1
    jz .pp1
    or bl, 8
.pp1:
    mov [d_reg], bl
    mov byte [d_defsize8], 1
    mov byte [d_style], ST_OREG
    cmp al, 0x58
    jb .ppush
    lea rsi, [mn_pop]
    jmp .pp2
.ppush:
    lea rsi, [mn_push]
.pp2:
    mov [d_mnem], rsi
    ret
.c63:
    cmp al, 0x63                     ; movsxd r64, r/m32
    jne .c68
    lea rsi, [mn_movsxd]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 4
    call parse_modrm
    call read_disp
    ret
.c68:
    cmp al, 0x68                     ; push imm32
    jne .c6a
    lea rsi, [mn_push]
    mov [d_mnem], rsi
    mov byte [d_style], ST_IMM
    call set_imm_vsize
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.c6a:
    cmp al, 0x6a                     ; push imm8
    jne .c69
    lea rsi, [mn_push]
    mov [d_mnem], rsi
    mov byte [d_style], ST_IMM
    mov byte [d_imm_size], 1
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.c69:
    cmp al, 0x69                     ; imul r, r/m, imm32
    jne .c6b
    lea rsi, [mn_imul]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_IMM
    call parse_modrm
    call read_disp
    call set_imm_vsize
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.c6b:
    cmp al, 0x6b                     ; imul r, r/m, imm8
    jne .jcc8
    lea rsi, [mn_imul]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_IMM
    call parse_modrm
    call read_disp
    mov byte [d_imm_size], 1
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.jcc8:
    ; --- jcc rel8 (0x70..0x7F) ---
    cmp al, 0x70
    jb .grp1
    cmp al, 0x7f
    ja .grp1
    mov bl, al
    and bl, 0xf
    movzx ebx, bl
    lea rax, [jcc_tbl]
    mov rsi, [rax + rbx*8]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 1
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.grp1:
    ; --- group1 arithmetic with immediate (0x80..0x83) ---
    cmp al, 0x80
    jb .c84
    cmp al, 0x83
    ja .c84
    cmp al, 0x81
    je .g1v
    cmp al, 0x80
    je .g1b
    cmp al, 0x82
    je .g1b
    jmp .g1parse                    ; 0x83
.g1b:
    mov byte [d_byte], 1
.g1parse:
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_arith]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    cmp byte [d_op], 0x81
    je .g1immv
    mov byte [d_imm_size], 1
    cmp byte [d_op], 0x83
    jne .g1rd
    mov byte [d_imm_signed], 1
.g1rd:
    call read_imm
    ret
.g1v:
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_arith]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
.g1immv:
    call set_imm_vsize
    call read_imm
    ret
.c84:
    cmp al, 0x84                     ; test r/m8, r8
    jne .c85
    mov byte [d_byte], 1
    lea rsi, [mn_test]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c85:
    cmp al, 0x85                     ; test r/m, r
    jne .c86
    lea rsi, [mn_test]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c86:
    cmp al, 0x86                     ; xchg r/m8, r8
    jne .c87
    mov byte [d_byte], 1
    lea rsi, [mn_xchg]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c87:
    cmp al, 0x87                     ; xchg r/m, r
    jne .c88
    lea rsi, [mn_xchg]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c88:
    cmp al, 0x88                     ; mov r/m8, r8
    jne .c89
    mov byte [d_byte], 1
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c89:
    cmp al, 0x89                     ; mov r/m, r
    jne .c8a
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_REG
    call parse_modrm
    call read_disp
    ret
.c8a:
    cmp al, 0x8a                     ; mov r8, r/m8
    jne .c8b
    mov byte [d_byte], 1
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.c8b:
    cmp al, 0x8b                     ; mov r, r/m
    jne .c8d
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.c8d:
    cmp al, 0x8d                     ; lea r, m
    jne .c8f
    lea rsi, [mn_lea]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM
    mov byte [d_nosize], 1
    call parse_modrm
    call read_disp
    ret
.c8f:
    cmp al, 0x8f                     ; pop r/m
    jne .c90
    lea rsi, [mn_pop]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM
    mov byte [d_defsize8], 1
    call parse_modrm
    call read_disp
    ret
.c90:
    cmp al, 0x90                     ; nop
    jne .c98
    lea rsi, [mn_nop]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.c98:
    cmp al, 0x98                     ; cwde / cdqe
    jne .c99
    test byte [d_rex], 8
    jz .c98w
    lea rsi, [mn_cdqe]
    jmp .c98s
.c98w:
    lea rsi, [mn_cwde]
.c98s:
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.c99:
    cmp al, 0x99                     ; cdq / cqo
    jne .ca8
    test byte [d_rex], 8
    jz .c99w
    lea rsi, [mn_cqo]
    jmp .c99s
.c99w:
    lea rsi, [mn_cdq]
.c99s:
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.ca8:
    cmp al, 0xa8                     ; test al, imm8
    jne .ca9
    mov byte [d_byte], 1
    lea rsi, [mn_test]
    mov [d_mnem], rsi
    mov byte [d_style], ST_ACC_IMM
    mov byte [d_imm_size], 1
    call read_imm
    ret
.ca9:
    cmp al, 0xa9                     ; test eAX, imm
    jne .cb0
    lea rsi, [mn_test]
    mov [d_mnem], rsi
    mov byte [d_style], ST_ACC_IMM
    call set_imm_vsize
    call read_imm
    ret
.cb0:
    cmp al, 0xb0                     ; mov r8, imm8
    jb .cb8
    cmp al, 0xb7
    ja .cb8
    mov bl, al
    and bl, 7
    test byte [d_rex], 1
    jz .b0r
    or bl, 8
.b0r:
    mov [d_reg], bl
    mov byte [d_byte], 1
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_IMM
    mov byte [d_imm_size], 1
    call read_imm
    ret
.cb8:
    cmp al, 0xb8                     ; mov r, imm (movabs if REX.W)
    jb .cc0
    cmp al, 0xbf
    ja .cc0
    mov bl, al
    and bl, 7
    test byte [d_rex], 1
    jz .b8r
    or bl, 8
.b8r:
    mov [d_reg], bl
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_IMM
    test byte [d_rex], 8
    jz .b8_32
    mov byte [d_imm_size], 8
    jmp .b8_rd
.b8_32:
    call set_imm_vsize
.b8_rd:
    call read_imm
    ret
.cc0:
    cmp al, 0xc0                     ; shift group r/m, imm8
    jne .cc1
    mov byte [d_byte], 1
.cc0common:
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_shift]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    mov byte [d_imm_size], 1
    call read_imm
    ret
.cc1:
    cmp al, 0xc1
    jne .cc2
    jmp .cc0common
.cc2:
    cmp al, 0xc2                     ; ret imm16
    jne .cc3
    lea rsi, [mn_ret]
    mov [d_mnem], rsi
    mov byte [d_style], ST_IMM
    mov byte [d_imm_size], 2
    call read_imm
    ret
.cc3:
    cmp al, 0xc3                     ; ret
    jne .cc6
    lea rsi, [mn_ret]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.cc6:
    cmp al, 0xc6                     ; mov r/m8, imm8
    jne .cc7
    mov byte [d_byte], 1
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    mov byte [d_imm_size], 1
    call read_imm
    ret
.cc7:
    cmp al, 0xc7                     ; mov r/m, imm
    jne .cc9
    lea rsi, [mn_mov]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM_IMM
    call parse_modrm
    call read_disp
    call set_imm_vsize
    mov byte [d_imm_signed], 1
    call read_imm
    ret
.cc9:
    cmp al, 0xc9                     ; leave
    jne .ccc
    lea rsi, [mn_leave]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.ccc:
    cmp al, 0xcc                     ; int3
    jne .cd0
    lea rsi, [mn_int3]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.cd0:
    cmp al, 0xd0                     ; shift r/m, 1
    jne .cd1
    mov byte [d_byte], 1
.cd0common:
    mov byte [d_style], ST_RM_1
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_shift]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    ret
.cd1:
    cmp al, 0xd1
    jne .cd2
    jmp .cd0common
.cd2:
    cmp al, 0xd2                     ; shift r/m, cl
    jne .cd3
    mov byte [d_byte], 1
.cd2common:
    mov byte [d_style], ST_RM_CL
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_shift]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    ret
.cd3:
    cmp al, 0xd3
    jne .ce8
    jmp .cd2common
.ce8:
    cmp al, 0xe8                     ; call rel32
    jne .ce9
    lea rsi, [mn_call]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 4
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.ce9:
    cmp al, 0xe9                     ; jmp rel32
    jne .ceb
    lea rsi, [mn_jmp]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 4
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.ceb:
    cmp al, 0xeb                     ; jmp rel8
    jne .cf4
    lea rsi, [mn_jmp]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 1
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.cf4:
    cmp al, 0xf4                     ; hlt
    jne .cf6
    lea rsi, [mn_hlt]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.cf6:
    cmp al, 0xf6                     ; group3 byte
    jne .cf7
    mov byte [d_byte], 1
.cf6common:
    call parse_modrm
    call read_disp
    movzx ecx, byte [d_reg]
    and ecx, 7
    lea rax, [grp_f7]
    mov rsi, [rax + rcx*8]
    mov [d_mnem], rsi
    cmp ecx, 2                       ; reg 0/1 = test (has imm)
    jae .f6_rm
    mov byte [d_style], ST_RM_IMM
    cmp byte [d_op], 0xf6
    je .f6_imm8
    call set_imm_vsize
    call read_imm
    ret
.f6_imm8:
    mov byte [d_imm_size], 1
    call read_imm
    ret
.f6_rm:
    mov byte [d_style], ST_RM
    ret
.cf7:
    cmp al, 0xf7                     ; group3
    jne .cfe
    jmp .cf6common
.cfe:
    cmp al, 0xfe                     ; group4 inc/dec r/m8
    jne .cff
    mov byte [d_byte], 1
    call parse_modrm
    call read_disp
    mov byte [d_style], ST_RM
    movzx ecx, byte [d_reg]
    and ecx, 7
    cmp ecx, 0
    jne .fe_dec
    lea rsi, [mn_inc]
    jmp .fe_set
.fe_dec:
    lea rsi, [mn_dec]
.fe_set:
    mov [d_mnem], rsi
    ret
.cff:
    cmp al, 0xff                     ; group5
    jne .cstr
    call parse_modrm
    call read_disp
    mov byte [d_style], ST_RM
    movzx ecx, byte [d_reg]
    and ecx, 7
    cmp ecx, 0
    je .ff_inc
    cmp ecx, 1
    je .ff_dec
    cmp ecx, 2
    je .ff_call
    cmp ecx, 4
    je .ff_jmp
    cmp ecx, 6
    je .ff_push
    jmp .unknown
.ff_inc:
    lea rsi, [mn_inc]
    mov [d_mnem], rsi
    ret
.ff_dec:
    lea rsi, [mn_dec]
    mov [d_mnem], rsi
    ret
.ff_call:
    lea rsi, [mn_call]
    mov [d_mnem], rsi
    mov byte [d_defsize8], 1
    ret
.ff_jmp:
    lea rsi, [mn_jmp]
    mov [d_mnem], rsi
    mov byte [d_defsize8], 1
    ret
.ff_push:
    lea rsi, [mn_push]
    mov [d_mnem], rsi
    mov byte [d_defsize8], 1
    ret
.cstr:
    ; string operations: movs/cmps/stos/lods/scas (0xA4..0xA7, 0xAA..0xAF)
    cmp al, 0xa4
    jb .unknown
    cmp al, 0xa7
    jbe .cstr_do
    cmp al, 0xaa
    jb .unknown
    cmp al, 0xaf
    ja .unknown
.cstr_do:
    ; index into str_tbl = opcode - 0xa4
    movzx ecx, al
    sub ecx, 0xa4
    lea rax, [str_tbl]
    mov rsi, [rax + rcx*8]           ; base name pointer
    ; compose into strmnem: optional rep prefix, then base, then size suffix
    lea rdi, [strmnem]
    ; --- prefix ---
    cmp byte [d_rep], 1
    je .cstr_rep
    cmp byte [d_repne], 1
    je .cstr_repne
    jmp .cstr_base
.cstr_rep:
    ; cmps/scas use repz, others use rep
    cmp byte [d_op], 0xa6
    je .cstr_repz
    cmp byte [d_op], 0xa7
    je .cstr_repz
    cmp byte [d_op], 0xae
    je .cstr_repz
    cmp byte [d_op], 0xaf
    je .cstr_repz
    lea rbx, [pfx_rep]
    jmp .cstr_copy_pfx
.cstr_repz:
    lea rbx, [pfx_repz]
    jmp .cstr_copy_pfx
.cstr_repne:
    lea rbx, [pfx_repnz]
.cstr_copy_pfx:
    mov al, [rbx]
    test al, al
    jz .cstr_base
    mov [rdi], al
    inc rdi
    inc rbx
    jmp .cstr_copy_pfx
.cstr_base:
    mov al, [rsi]
    test al, al
    jz .cstr_suffix
    mov [rdi], al
    inc rdi
    inc rsi
    jmp .cstr_base
.cstr_suffix:
    ; even opcode -> byte 'b'; odd -> w/d/q by operand size
    test byte [d_op], 1
    jz .cstr_b
    test byte [d_rex], 8             ; REX.W -> q
    jnz .cstr_q
    cmp byte [d_opsize], 1           ; 0x66 -> w
    je .cstr_w
    mov al, 'd'
    jmp .cstr_put
.cstr_q:
    mov al, 'q'
    jmp .cstr_put
.cstr_w:
    mov al, 'w'
    jmp .cstr_put
.cstr_b:
    mov al, 'b'
.cstr_put:
    mov [rdi], al
    inc rdi
    mov byte [rdi], 0
    lea rsi, [strmnem]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.unknown:
    mov byte [d_style], 0xff
    ret

; decode_two_byte - in: al = second opcode byte (after 0x0F).
decode_two_byte:
    cmp al, 0x05                     ; syscall
    jne .t1e
    lea rsi, [mn_syscall]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.t1e:
    cmp al, 0x1e                     ; endbr64 / endbr32 / nop r/m
    jne .t1f
    mov byte [d_style], ST_NONE
    call parse_modrm
    call read_disp
    cmp byte [d_rep], 1
    jne .t1e_nop
    cmp byte [d_modrm], 0xfa
    jne .t1e_fb
    lea rsi, [mn_endbr64]
    mov [d_mnem], rsi
    ret
.t1e_fb:
    lea rsi, [mn_nop]
    mov [d_mnem], rsi
    ret
.t1e_nop:
    lea rsi, [mn_nop]
    mov [d_mnem], rsi
    ret
.t1f:
    cmp al, 0x1f                     ; multi-byte nop r/m
    jne .t80
    lea rsi, [mn_nop]
    mov [d_mnem], rsi
    mov byte [d_style], ST_RM
    call parse_modrm
    call read_disp
    ret
.t80:
    cmp al, 0x80                     ; jcc rel32
    jb .t90
    cmp al, 0x8f
    ja .t90
    mov bl, al
    and bl, 0xf
    movzx ebx, bl
    lea rax, [jcc_tbl]
    mov rsi, [rax + rbx*8]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REL
    mov byte [d_imm_size], 4
    mov byte [d_imm_signed], 1
    mov byte [d_is_rel], 1
    call read_imm
    ret
.t90:
    cmp al, 0x90                     ; setcc r/m8
    jb .ta2
    cmp al, 0x9f
    ja .ta2
    mov bl, al
    and bl, 0xf
    movzx ebx, bl
    lea rax, [set_tbl]
    mov rsi, [rax + rbx*8]
    mov [d_mnem], rsi
    mov byte [d_byte], 1
    mov byte [d_style], ST_RM
    call parse_modrm
    call read_disp
    ret
.ta2:
    cmp al, 0xa2                     ; cpuid
    jne .taf
    lea rsi, [mn_cpuid]
    mov [d_mnem], rsi
    mov byte [d_style], ST_NONE
    ret
.taf:
    cmp al, 0xaf                     ; imul r, r/m
    jne .tb6
    lea rsi, [mn_imul]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM
    call parse_modrm
    call read_disp
    ret
.tb6:
    cmp al, 0xb6                     ; movzx r, r/m8
    jne .tb7
    lea rsi, [mn_movzx]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 1
    call parse_modrm
    call read_disp
    ret
.tb7:
    cmp al, 0xb7                     ; movzx r, r/m16
    jne .tbe
    lea rsi, [mn_movzx]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 2
    call parse_modrm
    call read_disp
    ret
.tbe:
    cmp al, 0xbe                     ; movsx r, r/m8
    jne .tbf
    lea rsi, [mn_movsx]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 1
    call parse_modrm
    call read_disp
    ret
.tbf:
    cmp al, 0xbf                     ; movsx r, r/m16
    jne .tunknown
    lea rsi, [mn_movsx]
    mov [d_mnem], rsi
    mov byte [d_style], ST_REG_RM_B
    mov byte [d_srcsz], 2
    call parse_modrm
    call read_disp
    ret
.tunknown:
    mov byte [d_style], 0xff
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
