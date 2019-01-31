# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.


import math
from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    import lief
    HAVE_LIEF = True
except:
    HAVE_LIEF = False

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


class Lief(Module):
    cmd         = "lief"
    description = "Parse and extract information from ELF, PE, MachO, DEX, OAT, ART and VDEX formats"
    authors     = ["Jordan Samhi"]

    def __init__(self):
        super(Lief, self).__init__()
        subparsers  = self.parser.add_subparsers(dest="subname")
        subparsers.add_parser("sections", help="List binary sections")
        subparsers.add_parser("segments", help="List binary segments")
        subparsers.add_parser("type", help="Show binary type")
        subparsers.add_parser("architecture", help="Show binary architecture")
        subparsers.add_parser("entropy", help="Show binary entropy")
        subparsers.add_parser("entrypoint", help="Show binary entrypoint")
        subparsers.add_parser("interpreter", help="Show binary interpreter")
        subparsers.add_parser("symbols", help="Show binary symbols")
        subparsers.add_parser("dynamic", help="Show binary dynamic libraries")
        self.lief = None
    
    def __check_session(self):
        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            return False
        if not self.lief:
            try:
                self.lief       = lief.parse(__sessions__.current.file.path)
                self.filePath   = __sessions__.current.file.path
            except lief.parser_error as e:
                self.log("error", "Unable to parse file : {0}".format(e))
                return False
        return True
    
    def sections(self):
        if not self.__check_session():
            return

        rows = []

        # ELF   
        if lief.is_elf(self.filePath):
            for section in self.lief.sections:
                rows.append([
                    section.name,
                    hex(section.offset),
                    hex(section.virtual_address),
                    hex(section.size),
                    ELF_SECTION_TYPES[section.type],
                    ':'.join(ELF_SECTION_FLAGS[flag] for flag in section.flags_list),
                    round(section.entropy, 4)
                ])
            self.log("info", "ELF sections : ")
            self.log("table", dict(header=["Name", "Address", "RVA", "Size", "Type", "Flags", "Entropy"], rows=rows))

        # PE
        elif lief.is_pe(self.filePath):
            for section in self.lief.sections:
                rows.append([
                    section.name,
                    hex(section.virtual_address),
                    hex(section.virtual_size),
                    hex(section.offset),
                    section.size,
                    round(section.entropy, 4)
                ])

            self.log("info", "PE sections : ")
            self.log("table", dict(header=["Name","RVA", "VirtualSize", "PointerToRawData", "RawDataSize", "Entropy"], rows=rows))

        else:
            self.log("error", "No section found")
            return
    
    def segments(self):
        if not self.__check_session():
            return

        rows = []

        # ELF   
        if lief.is_elf(self.filePath):
            for segment in self.lief.segments:
                flags = []
                if lief.ELF.SEGMENT_FLAGS.R in segment:
                    flags.append(ELF_SEGMENT_FLAGS[lief.ELF.SEGMENT_FLAGS.R])
                if lief.ELF.SEGMENT_FLAGS.W in segment:
                    flags.append(ELF_SEGMENT_FLAGS[lief.ELF.SEGMENT_FLAGS.W])
                if lief.ELF.SEGMENT_FLAGS.X in segment:
                    flags.append(ELF_SEGMENT_FLAGS[lief.ELF.SEGMENT_FLAGS.X])
                if lief.ELF.SEGMENT_FLAGS.NONE in segment:
                    flags.append(ELF_SEGMENT_FLAGS[lief.ELF.SEGMENT_FLAGS.NONE])
                rows.append([
                    ELF_SEGMENT_TYPES[segment.type],
                    hex(segment.physical_address),
                    hex(segment.physical_size),
                    hex(segment.virtual_address),
                    hex(segment.virtual_size),
                    ':'.join(flag for flag in flags),
                    self.getEntropy(bytes(segment.content))
                ])
            self.log("info", "ELF segments : ")
            self.log("table", dict(header=["Type", "PhysicalAddress", "FileSize", "VirtuAddr", "MemSize", "Flags", "Entropy"], rows=rows))
        else:
            self.log("error", "No segment found")

    def type(self):
        if not self.__check_session():
            return

        # ELF   
        if lief.is_elf(self.filePath):
            self.log("info", "Type : " + ELF_ETYPE[self.lief.header.file_type])
        else:
            self.log("error", "No type found")

    
    def entrypoint(self):
        if not self.__check_session():
            return

        # ELF   
        if lief.is_elf(self.filePath):
            self.log("info", "Entry point : " + hex(self.lief.header.entrypoint))
        else:
            self.log("error", "No entrypoint found")
    
    def architecture(self):
        if not self.__check_session():
            return

        # ELF   
        if lief.is_elf(self.filePath):
            self.log("info", "Architecture : " + str(self.lief.header.machine_type).split('.')[1])
        else:
            self.log("error", "No architecture found")

    def entropy(self):
        if not self.__check_session():
            return
        entropy = self.getEntropy(bytes(__sessions__.current.file.data))
        self.log("info", "Entropy : " + str(entropy))
        if entropy > 7:
            self.log("warning", "The binary is probably packed")


    def interpreter(self):
        if not self.__check_session():
            return

        # ELF   
        if lief.is_elf(self.filePath):
            self.log("info", "Interpreter : " + self.lief.interpreter)
        else:
            self.log("error", "No interpreter found")

    def dynamic(self):
        if not self.__check_session():
            return

        #ELF
        if lief.is_elf(self.filePath):
            for lib in self.lief.libraries:
                self.log("info", "Library : " + lib)
        else:
            self.log("error", "No dynamic library found")

    def symbols(self):
        if not self.__check_session():
            return

        rows = []

        # ELF   
        if lief.is_elf(self.filePath):
            for symbol in self.lief.symbols:
                rows.append([
                    symbol.name,
                    ELF_SYMBOL_TYPE[symbol.type],
                    hex(symbol.value),
                    hex(symbol.size),
                    ELF_SYMBOL_VISIBILITY[symbol.visibility],
                    'X' if symbol.is_function else '-',
                    'X' if symbol.is_static else '-',
                    'X' if symbol.is_variable else '-'
                ])
            self.log("info", "ELF symbols : ")
            self.log("table", dict(header=["Name", "Type", "Val", "Size", "Visibility", "isFunction", "isStatic", "isVariable"], rows=rows))
        else:
            self.log("error", "No symbol found")


    def getEntropy(self, data):
        if not data:
            return 0
        e = 0
        for i in range(256):
            p = float(data.count(bytes(i))) / len(data)
            if p > 0:
                e -= p * math.log(p, 2)
        entropy = round(e, 4)
        return entropy

    def run(self):
        super(Lief, self).run()
        if self.args is None:
            return

        if not HAVE_LIEF:
            self.log("error", "Missing dependency, install lief (pip3 install lief)")
            return

        if self.args.subname == "sections":
            self.sections()
        elif self.args.subname == "segments":
            self.segments()
        elif self.args.subname == "type":
            self.type()
        elif self.args.subname == "entrypoint":
            self.entrypoint()
        elif self.args.subname == "architecture":
            self.architecture()
        elif self.args.subname == "entropy":
            self.entropy()
        elif self.args.subname == "interpreter":
            self.interpreter()
        elif self.args.subname == "symbols":
            self.symbols()
        elif self.args.subname == "dynamic":
            self.dynamic()
        else:
            self.log("error", "At least one of the parameters is required")
            self.usage()
