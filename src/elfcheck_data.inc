section .rodata
    elf_magic:      db 0x7f, 'E', 'L', 'F'

    usage_msg:      db "Usage: elfcheck [options] <file>", 10
                    db "  Output modes:   --json   --disasm | -d   --function <name>", 10
                    db "                   --triage | -t  (flag anomalies, exit 2 on HIGH/MED)", 10
                    db "  Disasm range:   --start-address <hex> --count <n>", 10
                    db "  Section filters: --header --segments --sections --validate --security", 10
                    db "                   --dynamic --hardening --notes (shown by default)", 10
                    db "                   --symbols --relocs (opt-in tables)", 10
                    db "  --help | -h     show this help", 10
    usage_len:      equ $ - usage_msg

    opt_json:       db "--json", 0
    opt_header:     db "--header", 0
    opt_segments:   db "--segments", 0
    opt_sections:   db "--sections", 0
    opt_validate:   db "--validate", 0
    opt_security:   db "--security", 0
    opt_dynamic:    db "--dynamic", 0
    opt_hardening:  db "--hardening", 0
    opt_symbols:    db "--symbols", 0
    opt_relocs:     db "--relocs", 0
    opt_notes:      db "--notes", 0
    opt_help:       db "--help", 0
    opt_help_s:     db "-h", 0

    open_err_msg:   db "elfcheck: error: cannot open file", 10
    open_err_len:   equ $ - open_err_msg

    read_err_msg:   db "elfcheck: error: cannot read file", 10
    read_err_len:   equ $ - read_err_msg

    invalid_msg:    db "elfcheck: not an ELF file (bad magic)", 10
    invalid_len:    equ $ - invalid_msg

    trunc_msg:      db "elfcheck: error: truncated ELF header", 10
    trunc_len:      equ $ - trunc_msg

    unsupported_msg: db "elfcheck: error: only ELF64 little-endian files are supported", 10
    unsupported_len: equ $ - unsupported_msg

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
    m_eiversion:    db "unexpected e_ident version=", 0
    m_eversion:     db "unexpected e_version=", 0
    m_exp1:         db " (expected 1)", 0
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

    ; ---- symbol table report ----
    sym_title:      db 10, "Symbol Tables:", 10, 0
    sym_none:       db "  (no symbol tables found)", 10, 0
    sym_table_pre:  db "Symbol table '", 0
    sym_table_mid:  db "' (index ", 0
    sym_table_cnt:  db ") contains ", 0
    sym_table_end:  db " entries:", 10, 0
    sym_colhdr:     db "  Num   Value               Size Type       Bind       Vis        Ndx      Name", 10, 0
    sym_bad_meta:   db "  [!] invalid symbol table metadata; entries skipped", 10, 0
    sym_bad_strtab: db "  [!] invalid or unavailable linked string table; names omitted", 10, 0
    sym_type_symtab:db "SYMTAB", 0
    sym_type_dynsym:db "DYNSYM", 0
    sym_und:        db "UND", 0
    sym_abs:        db "ABS", 0
    sym_com:        db "COM", 0
    sym_xindex:     db "XINDEX", 0
    sym_notype:     db "NOTYPE", 0
    sym_object:     db "OBJECT", 0
    sym_func:       db "FUNC", 0
    sym_section:    db "SECTION", 0
    sym_file:       db "FILE", 0
    sym_common:     db "COMMON", 0
    sym_tls:        db "TLS", 0
    sym_ifunc:      db "IFUNC", 0
    sym_local:      db "LOCAL", 0
    sym_global:     db "GLOBAL", 0
    sym_weak:       db "WEAK", 0
    sym_unique:     db "UNIQUE", 0
    sym_default:    db "DEFAULT", 0
    sym_internal:   db "INTERNAL", 0
    sym_hidden:     db "HIDDEN", 0
    sym_protected:  db "PROTECTED", 0
    sym_unknown:    db "UNKNOWN", 0
    sym_version_at: db "@", 0
    sym_version_atat: db "@@", 0
    sym_version_required: db "required", 0
    sym_version_defined: db "defined", 0

    ; ---- relocation report ----
    rel_title:      db 10, "Relocations:", 10, 0
    rel_none:       db "  (no relocation sections found)", 10, 0
    rel_table_pre:  db "Relocation section '", 0
    rel_table_mid:  db "' (index ", 0
    rel_kind_mid:   db ", ", 0
    rel_target_mid: db ", target: ", 0
    rel_count_mid:  db ", ", 0
    rel_entries_end:db " entries):", 10, 0
    rel_target_none:db "none", 0
    rel_colhdr:     db "  Offset             Type                              TypeID  Sym     Symbol                         Addend", 10, 0
    rel_bad_meta:   db "  [!] invalid relocation section metadata; entries skipped", 10, 0
    rel_bad_symtab: db "  [!] invalid or unavailable linked symbol table; names unresolved", 10, 0
    rel_bad_strtab: db "  [!] invalid or unavailable symbol string table; names omitted", 10, 0
    rel_no_symbol:  db "-", 0
    rel_unresolved: db "<unresolved>", 0
    rel_minus:      db "-", 0
    rel_kind_rel:   db "REL", 0
    rel_kind_rela:  db "RELA", 0
    rel_type_unknown: db "R_X86_64_UNKNOWN", 0
    rel_type_other: db "UNKNOWN", 0
    rt_none:        db "R_X86_64_NONE", 0
    rt_64:          db "R_X86_64_64", 0
    rt_pc32:        db "R_X86_64_PC32", 0
    rt_got32:       db "R_X86_64_GOT32", 0
    rt_plt32:       db "R_X86_64_PLT32", 0
    rt_copy:        db "R_X86_64_COPY", 0
    rt_glob_dat:    db "R_X86_64_GLOB_DAT", 0
    rt_jump_slot:   db "R_X86_64_JUMP_SLOT", 0
    rt_relative:    db "R_X86_64_RELATIVE", 0
    rt_gotpc_rel:   db "R_X86_64_GOTPCREL", 0
    rt_32:          db "R_X86_64_32", 0
    rt_32s:         db "R_X86_64_32S", 0
    rt_16:          db "R_X86_64_16", 0
    rt_pc16:        db "R_X86_64_PC16", 0
    rt_8:           db "R_X86_64_8", 0
    rt_pc8:         db "R_X86_64_PC8", 0
    rt_dtpmod64:    db "R_X86_64_DTPMOD64", 0
    rt_dtpoff64:    db "R_X86_64_DTPOFF64", 0
    rt_tpoff64:     db "R_X86_64_TPOFF64", 0
    rt_tls_gd:      db "R_X86_64_TLSGD", 0
    rt_tls_ld:      db "R_X86_64_TLSLD", 0
    rt_dtpoff32:   db "R_X86_64_DTPOFF32", 0
    rt_gottpoff:    db "R_X86_64_GOTTPOFF", 0
    rt_tpoff32:     db "R_X86_64_TPOFF32", 0
    rt_pc64:        db "R_X86_64_PC64", 0
    rt_gotoff64:    db "R_X86_64_GOTOFF64", 0
    rt_gotpc32:     db "R_X86_64_GOTPC32", 0
    rt_got64:       db "R_X86_64_GOT64", 0
    rt_gotpcrel64:  db "R_X86_64_GOTPCREL64", 0
    rt_gotpc64:     db "R_X86_64_GOTPC64", 0
    rt_gotplt64:    db "R_X86_64_GOTPLT64", 0
    rt_pltoff64:    db "R_X86_64_PLTOFF64", 0
    rt_size32:      db "R_X86_64_SIZE32", 0
    rt_size64:      db "R_X86_64_SIZE64", 0
    rt_gotpc32_tlsdesc: db "R_X86_64_GOTPC32_TLSDESC", 0
    rt_tlsdesc_call: db "R_X86_64_TLSDESC_CALL", 0
    rt_tlsdesc:     db "R_X86_64_TLSDESC", 0
    rt_irelative:   db "R_X86_64_IRELATIVE", 0
    rt_relative64:  db "R_X86_64_RELATIVE64", 0
    rt_gotpcrelx:   db "R_X86_64_GOTPCRELX", 0
    rt_rex_gotpcrelx: db "R_X86_64_REX_GOTPCRELX", 0

    ; ---- hardening report (checksec-style) ----
    hd_title:       db 10, "Hardening:", 10, 0
    hd_relro_lbl:   db "  RELRO:         ", 0
    hd_canary_lbl:  db "  Stack canary:  ", 0
    hd_nx_lbl:      db "  NX:            ", 0
    hd_pie_lbl:     db "  PIE:           ", 0
    hd_ibt_lbl:     db "  IBT:           ", 0
    hd_shstk_lbl:   db "  SHSTK:         ", 0
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
    hd_unknown_cet: db "unknown (no GNU feature property)", 10, 0
    hd_dso:         db "shared object", 10, 0
    hd_na:          db "n/a", 10, 0
    hd_notset:      db "not set", 10, 0
    hd_fortify_fns: db " fortified function(s)", 10, 0
    name_stackchk:  db "__stack_chk_fail", 0

    ; ---- notes (readelf -n) ----
    notes_title:    db 10, "Notes:", 10, 0
    notes_none:     db "  (none)", 10, 0
    note_buildid_lbl: db "  Build ID: ", 0
    note_abi_lbl:   db "  ABI: ", 0
    note_props_lbl: db "  Properties: ", 0
    note_x86_feat:  db "x86 feature: ", 0
    note_feat_ibt:  db "IBT", 0
    note_feat_shstk: db "SHSTK", 0
    note_feat_none: db "none", 0
    note_owner_lbl: db "  ", 0
    note_type_lbl:  db ", type ", 0
    note_descsz_lbl: db ", descsz ", 0
    note_os_linux:  db "Linux ", 0
    note_os_gnu:    db "GNU ", 0
    note_os_solaris: db "Solaris ", 0
    note_os_freebsd: db "FreeBSD ", 0
    note_os_netbsd: db "NetBSD ", 0
    note_os_unknown: db "OS ", 0
    note_dot:       db ".", 0
    note_comma_sp:  db ", ", 0

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
    jk_symbol_tables: db 34, "symbol_tables", 34, ":", 0
    jk_symbols:     db 34, "symbols", 34, ":", 0
    jk_kind:        db 34, "kind", 34, ":", 0
    jk_version:     db 34, "version", 34, ":", 0
    jk_library:     db 34, "library", 34, ":", 0
    jk_hidden:      db 34, "hidden", 34, ":", 0
    jk_entry_count: db 34, "entry_count", 34, ":", 0
    jk_value:       db 34, "value", 34, ":", 0
    jk_binding:     db 34, "binding", 34, ":", 0
    jk_visibility:  db 34, "visibility", 34, ":", 0
    jk_section_index: db 34, "section_index", 34, ":", 0
    jk_section_kind: db 34, "section_kind", 34, ":", 0
    jk_strings_valid: db 34, "string_table_valid", 34, ":", 0
    jk_relocation_tables: db 34, "relocation_tables", 34, ":", 0
    jk_relocations: db 34, "relocations", 34, ":", 0
    jk_target_index: db 34, "target_index", 34, ":", 0
    jk_target_name: db 34, "target_name", 34, ":", 0
    jk_type_id:     db 34, "type_id", 34, ":", 0
    jk_symbol_index: db 34, "symbol_index", 34, ":", 0
    jk_symbol_name: db 34, "symbol_name", 34, ":", 0
    jk_addend:      db 34, "addend", 34, ":", 0
    jk_symbol_table_valid: db 34, "symbol_table_valid", 34, ":", 0
    jk_notes:       db 34, "notes", 34, ":", 0
    jk_owner:       db 34, "owner", 34, ":", 0
    jk_descsz:      db 34, "descsz", 34, ":", 0
    jk_desc:        db 34, "desc", 34, ":", 0
    jk_hardening:   db 34, "hardening", 34, ":", 0
    jk_relro:       db 34, "relro", 34, ":", 0
    jk_canary:      db 34, "stack_canary", 34, ":", 0
    jk_nx:          db 34, "nx", 34, ":", 0
    jk_pie:         db 34, "pie", 34, ":", 0
    jk_ibt:         db 34, "ibt", 34, ":", 0
    jk_shstk:       db 34, "shstk", 34, ":", 0
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
    dis_function_title: db 10, "Disassembly of function ", 0
    dis_function_section: db " in section ", 0
    dis_colon_nl:   db ":", 10, 0
    dis_sym_open:   db " <", 0
    dis_sym_close:  db ">", 0
    dis_reloc_open: db " [", 0
    dis_reloc_close: db "]", 0
    dis_nosect:     db "elfcheck: no executable .text section to disassemble", 10
    dis_nosect_len: equ $ - dis_nosect
    func_err_not_found: db "elfcheck: function not found: ", 0
    func_err_no_range: db "elfcheck: function has no usable executable range: ", 0
    dis_start_err:  db "elfcheck: error: start address is outside selected executable section", 10, 0
    dis_trunc_note: db "  ... (section larger than buffer; output truncated)", 10, 0
    dis_count_note: db "  ... (instruction limit reached)", 10, 0
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

    ; memory-size keywords indexed by operand byte size.
    sz_byte:        db "byte ", 0
    sz_word:        db "word ", 0
    sz_dword:       db "dword ", 0
    sz_qword:       db "qword ", 0
    sz_xmmword:     db "xmmword ", 0
    sz_ymmword:     db "ymmword ", 0
    sz_tbl:         dq sz_byte, sz_word, sz_dword, sz_qword, sz_xmmword, sz_ymmword

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

    xmm_0:  db "xmm0",0
    xmm_1:  db "xmm1",0
    xmm_2:  db "xmm2",0
    xmm_3:  db "xmm3",0
    xmm_4:  db "xmm4",0
    xmm_5:  db "xmm5",0
    xmm_6:  db "xmm6",0
    xmm_7:  db "xmm7",0
    xmm_8:  db "xmm8",0
    xmm_9:  db "xmm9",0
    xmm_10: db "xmm10",0
    xmm_11: db "xmm11",0
    xmm_12: db "xmm12",0
    xmm_13: db "xmm13",0
    xmm_14: db "xmm14",0
    xmm_15: db "xmm15",0
    regs_xmm: dq xmm_0,xmm_1,xmm_2,xmm_3,xmm_4,xmm_5,xmm_6,xmm_7
              dq xmm_8,xmm_9,xmm_10,xmm_11,xmm_12,xmm_13,xmm_14,xmm_15

    ymm_0:  db "ymm0",0
    ymm_1:  db "ymm1",0
    ymm_2:  db "ymm2",0
    ymm_3:  db "ymm3",0
    ymm_4:  db "ymm4",0
    ymm_5:  db "ymm5",0
    ymm_6:  db "ymm6",0
    ymm_7:  db "ymm7",0
    ymm_8:  db "ymm8",0
    ymm_9:  db "ymm9",0
    ymm_10: db "ymm10",0
    ymm_11: db "ymm11",0
    ymm_12: db "ymm12",0
    ymm_13: db "ymm13",0
    ymm_14: db "ymm14",0
    ymm_15: db "ymm15",0
    regs_ymm: dq ymm_0,ymm_1,ymm_2,ymm_3,ymm_4,ymm_5,ymm_6,ymm_7
              dq ymm_8,ymm_9,ymm_10,ymm_11,ymm_12,ymm_13,ymm_14,ymm_15

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
    mn_ud2:  db "ud2",0
    mn_movups: db "movups",0
    mn_movupd: db "movupd",0
    mn_movss: db "movss",0
    mn_movsd: db "movsd",0
    mn_movaps: db "movaps",0
    mn_movapd: db "movapd",0
    mn_andps: db "andps",0
    mn_andpd: db "andpd",0
    mn_andnps: db "andnps",0
    mn_andnpd: db "andnpd",0
    mn_orps: db "orps",0
    mn_orpd: db "orpd",0
    mn_xorps: db "xorps",0
    mn_xorpd: db "xorpd",0
    mn_addps: db "addps",0
    mn_addpd: db "addpd",0
    mn_mulps: db "mulps",0
    mn_mulpd: db "mulpd",0
    mn_subps: db "subps",0
    mn_subpd: db "subpd",0
    mn_minps: db "minps",0
    mn_minpd: db "minpd",0
    mn_divps: db "divps",0
    mn_divpd: db "divpd",0
    mn_maxps: db "maxps",0
    mn_maxpd: db "maxpd",0
    mn_vzeroupper: db "vzeroupper",0
    mn_vmovups: db "vmovups",0
    mn_vmovupd: db "vmovupd",0
    mn_vmovaps: db "vmovaps",0
    mn_vmovapd: db "vmovapd",0
    mn_vandps: db "vandps",0
    mn_vandpd: db "vandpd",0
    mn_vandnps: db "vandnps",0
    mn_vandnpd: db "vandnpd",0
    mn_vorps: db "vorps",0
    mn_vorpd: db "vorpd",0
    mn_vxorps: db "vxorps",0
    mn_vxorpd: db "vxorpd",0
    mn_vpand: db "vpand",0
    mn_vpandn: db "vpandn",0
    mn_vpor: db "vpor",0
    mn_vpxor: db "vpxor",0
    mn_vpaddb: db "vpaddb",0
    mn_vpaddw: db "vpaddw",0
    mn_vpaddd: db "vpaddd",0
    mn_vpaddq: db "vpaddq",0
    mn_vpsubb: db "vpsubb",0
    mn_vpsubw: db "vpsubw",0
    mn_vpsubd: db "vpsubd",0
    mn_vpsubq: db "vpsubq",0
    mn_vaddps: db "vaddps",0
    mn_vaddpd: db "vaddpd",0
    mn_vmulps: db "vmulps",0
    mn_vmulpd: db "vmulpd",0
    mn_vsubps: db "vsubps",0
    mn_vsubpd: db "vsubpd",0
    mn_vminps: db "vminps",0
    mn_vminpd: db "vminpd",0
    mn_vdivps: db "vdivps",0
    mn_vdivpd: db "vdivpd",0
    mn_vmaxps: db "vmaxps",0
    mn_vmaxpd: db "vmaxpd",0
    mn_vaddss: db "vaddss",0
    mn_vaddsd: db "vaddsd",0
    mn_vmulss: db "vmulss",0
    mn_vmulsd: db "vmulsd",0
    mn_vsubss: db "vsubss",0
    mn_vsubsd: db "vsubsd",0
    mn_vminss: db "vminss",0
    mn_vminsd: db "vminsd",0
    mn_vdivss: db "vdivss",0
    mn_vdivsd: db "vdivsd",0
    mn_vmaxss: db "vmaxss",0
    mn_vmaxsd: db "vmaxsd",0
    sse_ps_tbl: dq mn_andps,mn_andnps,mn_orps,mn_xorps,mn_addps,mn_mulps,0,0
                dq mn_subps,mn_minps,mn_divps,mn_maxps
    sse_pd_tbl: dq mn_andpd,mn_andnpd,mn_orpd,mn_xorpd,mn_addpd,mn_mulpd,0,0
                dq mn_subpd,mn_minpd,mn_divpd,mn_maxpd
    vex_ps_tbl: dq mn_vandps,mn_vandnps,mn_vorps,mn_vxorps,mn_vaddps,mn_vmulps,0,0
                dq mn_vsubps,mn_vminps,mn_vdivps,mn_vmaxps
    vex_pd_tbl: dq mn_vandpd,mn_vandnpd,mn_vorpd,mn_vxorpd,mn_vaddpd,mn_vmulpd,0,0
                dq mn_vsubpd,mn_vminpd,mn_vdivpd,mn_vmaxpd
    vex_ss_tbl: dq 0,0,0,0,mn_vaddss,mn_vmulss,0,0
                dq mn_vsubss,mn_vminss,mn_vdivss,mn_vmaxss
    vex_sd_tbl: dq 0,0,0,0,mn_vaddsd,mn_vmulsd,0,0
                dq mn_vsubsd,mn_vminsd,mn_vdivsd,mn_vmaxsd
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
    opt_function:   db "--function", 0
    opt_start_address: db "--start-address", 0
    opt_count:      db "--count", 0
    opt_triage:     db "--triage", 0
    opt_triage_s:   db "-t", 0

    ; ---- triage mode (severity-ranked anomaly scan) ----
    tri_title:      db "Triage:", 10, 0
    tri_lbl_high:   db "  [HIGH]   ", 0
    tri_lbl_med:    db "  [MED]    ", 0
    tri_lbl_low:    db "  [LOW]    ", 0
    tri_lbl_info:   db "  [INFO]   ", 0
    tri_m_struct:   db "structural inconsistencies in ELF layout", 0
    tri_m_wxseg:    db "writable and executable PT_LOAD segment (W^X)", 0
    tri_m_xstack:   db "executable stack (PT_GNU_STACK is RWX)", 0
    tri_m_textrel:  db "text relocations (code patched at load time)", 0
    tri_m_wxsect:   db "writable and executable section", 0
    tri_m_entry:    db "entry point not inside any executable segment", 0
    tri_m_noshdr:   db "no section headers (table stripped)", 0
    tri_m_norelro:  db "no RELRO (GOT is writable)", 0
    tri_m_partrelro: db "partial RELRO (GOT not fully protected)", 0
    tri_m_nopie:    db "no PIE (fixed load address)", 0
    tri_m_nocanary: db "no stack canary", 0
    tri_m_nocet:    db "CET not fully enabled (IBT/SHSTK)", 0
    tri_m_rpath:    db "RPATH set (insecure library search path)", 0
    tri_m_runpath:  db "RUNPATH set (library search path override)", 0
    tri_m_stripped: db "no symbol table (.symtab stripped)", 0
    tri_clean:      db "  Clean: no anomalies detected.", 10, 0
    tri_sum_pre:    db "  Summary: ", 0
    tri_sum_high:   db " high, ", 0
    tri_sum_med:    db " medium, ", 0
    tri_sum_low:    db " low, ", 0
    tri_sum_info:   db " info", 10, 0

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
    dsym_index:     resd 1             ; .dynsym section index
    dyn_is_static:  resb 1             ; 1 = no .dynamic section found
    hd_interp:      resb 1             ; 1 = PT_INTERP present
    hd_stack:       resb 1             ; 0 absent / 1 noexec / 2 exec (PT_GNU_STACK)
    hd_relro_seg:   resb 1             ; 1 = PT_GNU_RELRO present
    hd_bindnow:     resb 1             ; 1 = BIND_NOW (full RELRO)
    hd_canary:      resb 1             ; 1 = __stack_chk_fail imported
    hd_cet_seen:    resb 1             ; x86 FEATURE_1_AND GNU property found
    hd_cet_flags:   resd 1             ; GNU_PROPERTY_X86_FEATURE_1_* bits
    hd_flags1:      resq 1             ; DT_FLAGS_1 value
    hd_rpath_off:   resq 1             ; DT_RPATH dynstr offset, or -1
    hd_runpath_off: resq 1             ; DT_RUNPATH dynstr offset, or -1
    hd_fortify:     resq 1             ; count of imported *_chk functions
    note_range_off: resq 1
    note_range_size: resq 1
    note_cursor:    resq 1
    note_name_pad:  resq 1
    note_rel:       resq 1
    note_len:       resq 1
    note_desc_rel:  resq 1
    note_desc_size: resq 1
    note_desc_pad:  resq 1
    note_record_end: resq 1
    note_prop_cursor: resq 1
    note_prop_size: resq 1
    note_prop_pad:  resq 1
    note_prop_type: resd 1
    note_namesz:    resd 1
    note_type:      resd 1
    note_read_buf:  resq 1
    note_read_size: resq 1
    note_handler:   resq 1             ; per-record callback for scan_note_range
    note_count:     resq 1             ; notes printed so far (for "(none)")
    note_ranges_seen: resq 1           ; SHT_NOTE ranges found (segment fallback)
    note_desc_staged: resq 1           ; bytes staged into note_desc_buf
    note_owner:     resb 36            ; note name/owner string (NUL-terminated)
    note_desc_buf:  resb NOTE_DESC_CAP  ; staged note description bytes
    note_header:    resb 12
    note_name:      resb 4
    note_prop_header: resb 8
    note_prop_value: resb 4
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
    json_mode:      resb 1             ; 1 = emit JSON instead of report
    disasm_mode:    resb 1             ; 1 = disassemble machine code
    help_mode:      resb 1             ; 1 = --help/-h given
    disasm_error:   resb 1             ; 1 = targeted disassembly failed
    function_name:  resq 1             ; requested function name, or 0
    disasm_start_set: resb 1           ; 1 = --start-address supplied
    disasm_count_set: resb 1           ; 1 = --count supplied
    disasm_start_addr: resq 1          ; requested executable-section address
    disasm_count:   resq 1             ; maximum decoded instructions
    disasm_remaining: resq 1           ; instructions remaining in bounded report
    filter_mask:    resd 1             ; selected section bits (0 = use default sections)
    eff_mask:       resd 1             ; effective mask used while printing
    triage_mode:    resb 1             ; 1 = run the triage anomaly scan
    hd_textrel:     resb 1             ; 1 = DT_TEXTREL / DF_TEXTREL set (text relocs)
    tri_high:       resq 1             ; triage findings by severity
    tri_med:        resq 1
    tri_low:        resq 1
    tri_info:       resq 1
    tri_fail:       resb 1             ; 1 = triage CI gate tripped (exit 2)
    silent:         resb 1             ; 1 = validate_structure suppresses output
    jbuf:           resb 8             ; scratch for JSON byte escaping

    ; ---- symbol table state ----
    sym_json_mode:  resb 1
    sym_table_valid: resb 1
    sym_str_valid:  resb 1
    sym_table_first: resb 1
    sym_item_first: resb 1
    sym_table_index: resq 1
    sym_table_type: resd 1
    sym_table_name: resq 1
    sym_table_offset: resq 1
    sym_table_size: resq 1
    sym_table_entsize: resq 1
    sym_table_link: resd 1
    sym_entry_count: resq 1
    sym_entry_index: resq 1
    sym_tables_found: resq 1

    ; ---- GNU symbol versioning state ----
    ver_ready:       resb 1
    ver_versym_found: resb 1
    ver_need_found:  resb 1
    ver_def_found:   resb 1
    ver_dynsym_found: resb 1
    ver_versym_off:  resq 1
    ver_versym_size: resq 1
    ver_versym_link: resd 1
    ver_need_off:    resq 1
    ver_need_size:   resq 1
    ver_need_link:   resd 1
    ver_def_off:     resq 1
    ver_def_size:    resq 1
    ver_def_link:    resd 1
    ver_dynsym_link: resd 1
    ver_parse_off:   resq 1
    ver_parse_size:  resq 1
    ver_rel:         resq 1
    ver_bytes:       resq 1
    ver_read_off:    resq 1
    ver_read_buf:    resq 1
    ver_read_size:   resq 1
    ver_record_rel:  resq 1
    ver_aux_rel:     resq 1
    ver_aux_count:   resd 1
    ver_aux_index:   resd 1
    ver_cur_index:   resd 1
    ver_library_src: resd 1
    ver_copied_name: resd 1
    ver_copied_library: resd 1
    ver_copy_start:  resq 1
    ver_map_kind:    resb VER_MAP_COUNT
    ver_map_name:    resd VER_MAP_COUNT
    ver_map_library: resd VER_MAP_COUNT
    ver_strings_len: resq 1
    ver_strings:     resb VERSTR_CAP
    ver_need_record: resb 16
    ver_need_aux:    resb 16
    ver_def_record:  resb 20
    ver_def_aux:     resb 8
    ver_versym_entry: resb 2
    ver_lookup_table: resq 1
    ver_lookup_symbol: resq 1
    ver_lookup_index: resd 1
    ver_lookup_kind: resb 1
    ver_lookup_hidden: resb 1
    ver_lookup_name_off: resd 1
    ver_lookup_library_off: resd 1

    ; ---- relocation table state ----
    rel_json_mode:   resb 1
    rel_table_valid: resb 1
    rel_symtab_valid: resb 1
    rel_str_valid:   resb 1
    rel_target_valid: resb 1
    rel_table_first: resb 1
    rel_item_first:  resb 1
    rel_table_index: resq 1
    rel_table_type:  resd 1
    rel_table_name:  resq 1
    rel_table_offset: resq 1
    rel_table_size:  resq 1
    rel_table_entsize: resq 1
    rel_table_link:  resd 1
    rel_target_index: resd 1
    rel_target_name: resq 1
    rel_entry_count: resq 1
    rel_entry_index: resq 1
    rel_entry:       resb 24
    rel_offset:      resq 1
    rel_info:        resq 1
    rel_addend:      resq 1
    rel_type_id:     resd 1
    rel_symbol_index: resd 1
    rel_symbol_state: resb 1
    rel_symbol_name: resq 1
    rel_tables_found: resq 1

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
    d_vex_map:      resb 1             ; VEX opcode map
    d_vex_pp:       resb 1             ; VEX mandatory-prefix selector
    d_vex_l:        resb 1             ; VEX vector length (0=128, 1=256)
    d_vvvv:         resb 1             ; decoded VEX.vvvv register index
    d_style:        resb 1             ; operand rendering style (0xff = unknown)
    d_srcsz:        resb 1             ; source size for movzx/movsx
    d_vec:          resb 1             ; 0 = GPR, 1 = XMM, 2 = YMM
    d_vec_size:     resb 1             ; vector/memory operand width in bytes
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
    sel_index:      resq 1             ; section index for the selected range
    func_table_type: resd 1
    func_table_offset: resq 1
    func_table_size: resq 1
    func_table_entsize: resq 1
    func_table_link: resd 1
    func_table_current: resq 1
    func_table_count: resq 1
    func_symbol_seen: resb 1
    func_symbol_found: resb 1
    func_symbol_shndx: resd 1
    func_symbol_value: resq 1
    func_symbol_size: resq 1
    func_section_size: resq 1
    func_delta:     resq 1
    func_cache_count: resq 1
    func_cache_names_len: resq 1
    func_cache_values: resq FUNC_CACHE_CAP
    func_cache_name_offsets: resq FUNC_CACHE_CAP
    func_cache_names: resb DYNSTR_CAP
    d_rel_target:   resq 1
    reloc_cache_count: resq 1
    reloc_cache_names_len: resq 1
    reloc_cache_offsets: resq RELOC_CACHE_CAP
    reloc_cache_name_offsets: resq RELOC_CACHE_CAP
    reloc_cache_type_ids: resd RELOC_CACHE_CAP
    reloc_cache_names: resb DYNSTR_CAP
    reloc_cache_match_type: resd 1

