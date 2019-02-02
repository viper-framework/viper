import sys
try:
    import lief
    HAVE_LIEF = True
except:
    HAVE_LIEF = False

if not HAVE_LIEF:
    self.log("error", "Missing dependency, install lief (pip3 install lief)")
    sys.exit(1)

ELF_SECTION_FLAGS = {
    lief.ELF.SECTION_FLAGS.ALLOC                :    'A',
    lief.ELF.SECTION_FLAGS.EXECINSTR            :    'X',
    lief.ELF.SECTION_FLAGS.GROUP                :    'GR',
    lief.ELF.SECTION_FLAGS.HEX_GPREL            :    'H',
    lief.ELF.SECTION_FLAGS.EXCLUDE              :    'E',
    lief.ELF.SECTION_FLAGS.INFO_LINK            :    'I',
    lief.ELF.SECTION_FLAGS.LINK_ORDER           :    'L',
    lief.ELF.SECTION_FLAGS.MASKOS               :    'MA',
    lief.ELF.SECTION_FLAGS.MASKPROC             :    'MP',
    lief.ELF.SECTION_FLAGS.MERGE                :    'M',
    lief.ELF.SECTION_FLAGS.MIPS_ADDR            :    'M_A',
    lief.ELF.SECTION_FLAGS.MIPS_LOCAL           :    'M_L',
    lief.ELF.SECTION_FLAGS.MIPS_MERGE           :    'M_M',
    lief.ELF.SECTION_FLAGS.MIPS_NAMES           :    'M_N',
    lief.ELF.SECTION_FLAGS.MIPS_NODUPES         :    'M_ND',
    lief.ELF.SECTION_FLAGS.MIPS_NOSTRIP         :    'M_NS',
    lief.ELF.SECTION_FLAGS.NONE                 :    'N',
    lief.ELF.SECTION_FLAGS.OS_NONCONFORMING     :    'O',
    lief.ELF.SECTION_FLAGS.STRINGS              :    'S',
    lief.ELF.SECTION_FLAGS.TLS                  :    'T',
    lief.ELF.SECTION_FLAGS.WRITE                :    'W',
    lief.ELF.SECTION_FLAGS.XCORE_SHF_CP_SECTION :    'XC'
}

ELF_SECTION_TYPES = {
    lief.ELF.SECTION_TYPES.ARM_ATTRIBUTES       : "ARM_ATTRIBUTES",
    lief.ELF.SECTION_TYPES.ARM_DEBUGOVERLAY     : "ARM_DEBUGOVERLAY",
    lief.ELF.SECTION_TYPES.ARM_EXIDX            : "ARM_EXIDX",
    lief.ELF.SECTION_TYPES.ARM_OVERLAYSECTION   : "ARM_OVERLAYSECTION",
    lief.ELF.SECTION_TYPES.ARM_PREEMPTMAP       : "ARM_PREEMPTMAP",
    lief.ELF.SECTION_TYPES.DYNAMIC              : "DYNAMIC",
    lief.ELF.SECTION_TYPES.DYNSYM               : "DYNSYM",
    lief.ELF.SECTION_TYPES.FINI_ARRAY           : "FINI_ARRAY",
    lief.ELF.SECTION_TYPES.GNU_ATTRIBUTES       : "GNU_ATTRIBUTES",
    lief.ELF.SECTION_TYPES.GNU_HASH             : "GNU_HASH",
    lief.ELF.SECTION_TYPES.GNU_VERDEF           : "GNU_VERDEF",
    lief.ELF.SECTION_TYPES.GNU_VERNEED          : "GNU_VERNEED",
    lief.ELF.SECTION_TYPES.GNU_VERSYM           : "GNU_VERSYM",
    lief.ELF.SECTION_TYPES.GROUP                : "GROUP",
    lief.ELF.SECTION_TYPES.HASH                 : "HASH",
    lief.ELF.SECTION_TYPES.HIPROC               : "HIPROC",
    lief.ELF.SECTION_TYPES.HIUSER               : "HIUSER",
    lief.ELF.SECTION_TYPES.INIT_ARRAY           : "INIT_ARRAY",
    lief.ELF.SECTION_TYPES.LOOS                 : "LOOS",
    lief.ELF.SECTION_TYPES.LOPROC               : "LOPROC",
    lief.ELF.SECTION_TYPES.LOUSER               : "LOUSER",
    lief.ELF.SECTION_TYPES.MIPS_ABIFLAGS        : "MIPS_ABIFLAGS",
    lief.ELF.SECTION_TYPES.MIPS_OPTIONS         : "MIPS_OPTIONS",
    lief.ELF.SECTION_TYPES.MIPS_REGINFO         : "MIPS_REGINFO",
    lief.ELF.SECTION_TYPES.NOBITS               : "NOBITS",
    lief.ELF.SECTION_TYPES.NOTE                 : "NOTE",
    lief.ELF.SECTION_TYPES.NULL                 : "NULL",
    lief.ELF.SECTION_TYPES.PREINIT_ARRAY        : "PREINIT_ARRAY",
    lief.ELF.SECTION_TYPES.PROGBITS             : "PROGBITS",
    lief.ELF.SECTION_TYPES.REL                  : "REL",
    lief.ELF.SECTION_TYPES.RELA                 : "RELA",
    lief.ELF.SECTION_TYPES.SHLIB                : "SHLIB",
    lief.ELF.SECTION_TYPES.STRTAB               : "STRTAB",
    lief.ELF.SECTION_TYPES.SYMTAB               : "SYMTAB",
    lief.ELF.SECTION_TYPES.SYMTAB_SHNDX         : "SYMTAB_SHNDX",
}

ELF_SEGMENT_FLAGS = {
    lief.ELF.SEGMENT_FLAGS.R    :    'R',
    lief.ELF.SEGMENT_FLAGS.W    :    'W',
    lief.ELF.SEGMENT_FLAGS.X    :    'X',
    lief.ELF.SEGMENT_FLAGS.NONE :    'None'
}

ELF_SEGMENT_TYPES = {
    lief.ELF.SEGMENT_TYPES.NULL             :    "NULL",
    lief.ELF.SEGMENT_TYPES.LOAD             :    "LOAD",
    lief.ELF.SEGMENT_TYPES.DYNAMIC          :    "DYNAMIC",
    lief.ELF.SEGMENT_TYPES.INTERP           :    "INTERP",
    lief.ELF.SEGMENT_TYPES.NOTE             :    "NOTE",
    lief.ELF.SEGMENT_TYPES.SHLIB            :    "SHLIB",
    lief.ELF.SEGMENT_TYPES.PHDR             :    "PHDR",
    lief.ELF.SEGMENT_TYPES.TLS              :    "TLS",
    lief.ELF.SEGMENT_TYPES.LOOS             :    "LOOS",
    lief.ELF.SEGMENT_TYPES.HIOS             :    "HIOS",
    lief.ELF.SEGMENT_TYPES.LOPROC           :    "LOPROC",
    lief.ELF.SEGMENT_TYPES.HIPROC           :    "HIPROC",
    lief.ELF.SEGMENT_TYPES.GNU_EH_FRAME     :    "GNU_EH_FRAME",
    lief.ELF.SEGMENT_TYPES.SUNW_UNWIND      :    "SUNW_UNWIND",
    lief.ELF.SEGMENT_TYPES.GNU_STACK        :    "GNU_STACK",
    lief.ELF.SEGMENT_TYPES.GNU_RELRO        :    "GNU_RELRO",
    lief.ELF.SEGMENT_TYPES.ARM_EXIDX        :    "ARM_EXIDX",
    lief.ELF.SEGMENT_TYPES.MIPS_ABIFLAGS    :    "MIPS_ABIFLAGS",
    lief.ELF.SEGMENT_TYPES.MIPS_OPTIONS     :    "MIPS_OPTIONS",
}

ELF_ETYPE = {
    lief.ELF.E_TYPE.CORE        :   "CORE", 
    lief.ELF.E_TYPE.DYNAMIC     :   "DYNAMIC",
    lief.ELF.E_TYPE.EXECUTABLE  :   "EXECUTABLE",
    lief.ELF.E_TYPE.HIPROC      :   "HIPROC",
    lief.ELF.E_TYPE.LOPROC      :   "LOPROC",
    lief.ELF.E_TYPE.NONE        :   "NONE",
    lief.ELF.E_TYPE.RELOCATABLE :   "RELOCATABLE"
}

ELF_SYMBOL_VISIBILITY = {
    lief.ELF.SYMBOL_VISIBILITY.DEFAULT      :   "DEFAULT",
    lief.ELF.SYMBOL_VISIBILITY.HIDDEN       :   "HIDDEN",
    lief.ELF.SYMBOL_VISIBILITY.INTERNAL     :   "INTERNAL",
    lief.ELF.SYMBOL_VISIBILITY.PROTECTED    :   "PROTECTED"
}

ELF_SYMBOL_TYPE = {
    lief.ELF.SYMBOL_TYPES.COMMON     :   "COMMON",
    lief.ELF.SYMBOL_TYPES.FILE       :   "FILE",
    lief.ELF.SYMBOL_TYPES.HIOS       :   "HIOS",
    lief.ELF.SYMBOL_TYPES.HIPROC     :   "HIPROC",
    lief.ELF.SYMBOL_TYPES.LOPROC     :   "LOPROC",
    lief.ELF.SYMBOL_TYPES.NOTYPE     :   "NOTYPE",
    lief.ELF.SYMBOL_TYPES.OBJECT     :   "OBJECT",
    lief.ELF.SYMBOL_TYPES.SECTION    :   "SECTION",
    lief.ELF.SYMBOL_TYPES.TLS        :   "TLS",
    lief.ELF.SYMBOL_TYPES.FUNC       :   "FUNC"
}
