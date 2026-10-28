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

; All files below form one NASM translation unit.
%include "elfcheck_defs.inc"
%include "elfcheck_data.inc"
%include "elfcheck_main.inc"
%include "elfcheck_elf.inc"
%include "elfcheck_symbols.inc"
%include "elfcheck_dynamic.inc"
%include "elfcheck_hardening.inc"
%include "elfcheck_notes.inc"
%include "elfcheck_helpers.inc"
%include "elfcheck_json.inc"
%include "elfcheck_disasm.inc"
%include "elfcheck_format.inc"
