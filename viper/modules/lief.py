# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.


import math
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from datetime import datetime

try:
    import lief
    HAVE_LIEF = True
except:
    HAVE_LIEF = False

from .lief_imports.elf import *
from .lief_imports.pe import *
from .lief_imports.macho import *

class Lief(Module):
    cmd         = "lief"
    description = "Parse and extract information from ELF, PE, MachO, DEX, OAT, ART and VDEX formats"
    authors     = ["Jordan Samhi"]

    def __init__(self):
        super(Lief, self).__init__()
        subparsers  = self.parser.add_subparsers(dest="subname")
        
        parser_pe = subparsers.add_parser("pe", help="Extract information from PE files")
        parser_pe.add_argument("-s", "--sections", action="store_true", help="List PE sections")
        parser_pe.add_argument("-e", "--entrypoint", action="store_true", help="Show PE entrypoint")
        parser_pe.add_argument("-d", "--dlls", action="store_true", help="Show PE imported dlls")
        parser_pe.add_argument("-i", "--imports", action="store_true", help="Show PE imported functions")
        parser_pe.add_argument("-a", "--architecture", action="store_true", help="Show PE architecture")
        parser_pe.add_argument("-f", "--format", action="store_true", help="Show PE format")
        parser_pe.add_argument("-t", "--type", action="store_true", help="Show PE type")
        parser_pe.add_argument("-I", "--imphash", action="store_true", help="Show PE imported functions hash")
        parser_pe.add_argument("-c", "--compiledate", action="store_true", help="Show PE date of compilation")

        parser_elf = subparsers.add_parser("elf", help="Extract information from ELF files")
        parser_elf.add_argument("-S", "--segments", action="store_true", help="List ELF segments")
        parser_elf.add_argument("-s", "--sections", action="store_true", help="List ELF sections")
        parser_elf.add_argument("-y", "--symbols", action="store_true", help="Show ELF symbols")
        parser_elf.add_argument("-t", "--type", action="store_true", help="Show ELF type")
        parser_elf.add_argument("-e", "--entrypoint", action="store_true", help="Show ELF entrypoint")
        parser_elf.add_argument("-a", "--architecture", action="store_true", help="Show ELF architecture")
        parser_elf.add_argument("-i", "--interpreter", action="store_true", help="Show ELF interpreter")
        parser_elf.add_argument("-d", "--dynamic", action="store_true", help="Show ELF dynamic libraries")
        parser_elf.add_argument("-E", "--entropy", action="store_true", help="Show ELF entropy")

        parser_macho = subparsers.add_parser("macho", help="Extract information from MachO files")
        parser_macho.add_argument("-H", "--header", action="store_true", help="Show MachO header")
        parser_macho.add_argument("-e", "--entrypoint", action="store_true", help="Show MachO entrypoint")
        parser_macho.add_argument("-a", "--architecture", action="store_true", help="Show MachO architecture")
        parser_macho.add_argument("-t", "--type", action="store_true", help="Show MachO type")
        parser_macho.add_argument("-C", "--codesignature", action="store_true", help="Show MachO code signature")
        parser_macho.add_argument("-j", "--expfunctions", action="store_true", help="Show MachO exported functions")
        parser_macho.add_argument("-k", "--expsymbols", action="store_true", help="Show MachO exported symbols")
        parser_macho.add_argument("-g", "--impfunctions", action="store_true", help="Show MachO imported functions")
        parser_macho.add_argument("-q", "--impsymbols", action="store_true", help="Show MachO imported symbols")
        parser_macho.add_argument("-s", "--sections", action="store_true", help="Show MachO sections")
        parser_macho.add_argument("-S", "--segments", action="store_true", help="Show MachO segments")
        parser_macho.add_argument("-v", "--sourceversion", action="store_true", help="Show MachO source version")
        parser_macho.add_argument("-f", "--subframework", action="store_true", help="Show MachO sub-framework")
        parser_macho.add_argument("-u", "--uuid", action="store_true", help="Show MachO uuid")
        parser_macho.add_argument("-D", "--dataincode", action="store_true", help="Show MachO data in code")
        parser_macho.add_argument("-m", "--maincommand", action="store_true", help="Show MachO main command")
        parser_macho.add_argument("-c", "--commands", action="store_true", help="Show MachO commands")
        parser_macho.add_argument("-d", "--dynamic", action="store_true", help="Show MachO dynamic libraries")

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

    """Binaries methods"""
    
    def sections(self):
        if not self.__check_session():
            return
        rows = []
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
        elif lief.is_macho(self.filePath):
            for section in self.lief.sections:
                rows.append([
                    section.name,
                    hex(section.virtual_address),
                    MACHO_SECTION_TYPES[section.type],
                    "{:<6} bytes".format(section.size),
                    hex(section.offset),
                    round(section.entropy,4)
                ])
            self.log("info", "MachO sections : ")
            self.log("table", dict(header=["Name","Virt Addr", "Type", "Size", "Offset", "Entropy"], rows=rows))
        else:
            self.log("warning", "No section found")
            return
    
    def segments(self):
        if not self.__check_session():
            return
        rows = []
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
        elif lief.is_macho(self.filePath):
            self.log("info", "MachO segments : ")
            for segment in self.lief.segments:
                self.log("info", "Information of segment {0} : ".format(segment.name))
                self.log("item", "{0:<18} : {1}".format("Name", segment.name)),
                self.log("item", "{0:<18} : {1} Bytes".format("Size", segment.file_size)),
                self.log("item", "{0:<18} : {1}".format("Offset", segment.file_offset)),
                self.log("item", "{0:<18} : {1}".format("Command", MACHO_LOAD_COMMAND_TYPES[segment.command])),
                self.log("item", "{0:<18} : {1} Bytes".format("Command size", segment.size)),
                self.log("item", "{0:<18} : {1}".format("Command offset", hex(segment.command_offset))),
                self.log("item", "{0:<18} : {1}".format("Number of sections", segment.numberof_sections)),
                self.log("item", "{0:<18} : {1}".format("Initial protection", segment.init_protection)),
                self.log("item", "{0:<18} : {1}".format("Maximum protection", segment.max_protection)),
                self.log("item", "{0:<18} : {1}".format("Virtual address", hex(segment.virtual_address))),
                self.log("item", "{0:<18} : {1} Bytes".format("Virtual size", segment.virtual_size)),
                if segment.sections:
                    for section in segment.sections:
                        rows.append([
                            section.name,
                            hex(section.virtual_address),
                            MACHO_SECTION_TYPES[section.type],
                            "{:<6} bytes".format(section.size),
                            hex(section.offset),
                            round(section.entropy,4)
                        ])
                    self.log("success", "Sections in segment {0} : ".format(segment.name))
                    self.log("table", dict(header=["Name", "Virtual address", "Type", "Size", "Offset", "Entropy"], rows=rows))
                    rows = []
        else:
            self.log("warning", "No segment found")

    def type(self):
        if not self.__check_session():
            return
        if lief.is_elf(self.filePath):
            self.log("info", "Type : {0}".format(ELF_ETYPE[self.lief.header.file_type]))
        elif lief.is_pe(self.filePath):
            self.log("info", "Type : {0}".format(PE_TYPE[lief.PE.get_type(self.filePath)]))
        elif lief.is_macho(self.filePath):
            self.log("info", "Type : {0}".format(MACHO_FILE_TYPES[self.lief.header.file_type]))
        else:
            self.log("warning", "No type found")

    def entrypoint(self):
        if not self.__check_session():
            return
        if lief.is_elf(self.filePath):
            self.log("info", "Entry point : {0}".format(hex(self.lief.header.entrypoint)))
        elif lief.is_pe(self.filePath):
            self.log("info", "Entry point : {0}".format(hex(self.lief.entrypoint)))
        elif lief.is_macho(self.filePath):
            if self.lief.has_entrypoint:
                self.log("info", "Entrypoint : {0}".format(hex(self.lief.entrypoint)))
            else:
                self.log("warning", "No entrypoint found")
        else:
            self.log("warning", "No entrypoint found")
    
    def architecture(self):
        if not self.__check_session():
            return
        if lief.is_elf(self.filePath):
            self.log("info", "Architecture : {0}".format(ELF_MACHINE_TYPE[self.lief.header.machine_type]))
        elif lief.is_pe(self.filePath):
            self.log("info", "Architecture : {0}".format(PE_MACHINE_TYPE[self.lief.header.machine]))
        elif lief.is_macho(self.filePath):
            self.log("info", "Architecture : {0}".format(MACHO_CPU_TYPES[self.lief.header.cpu_type]))
        else:
            self.log("warning", "No architecture found")

    def entropy(self):
        if not self.__check_session():
            return
        entropy = self.getEntropy(bytes(__sessions__.current.file.data))
        self.log("info", "Entropy : {0}".format(str(entropy)))
        if entropy > 7:
            self.log("warning", "The binary is probably packed")

    def interpreter(self):
        if not self.__check_session():
            return
        if lief.is_elf(self.filePath):
            self.log("info", "Interpreter : {0}".format(self.lief.interpreter))
        else:
            self.log("warning", "No interpreter found")

    def dynamic(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_elf(self.filePath):
            for lib in self.lief.libraries:
                self.log("info", "Library : {0}".format(lib))
        elif lief.is_macho(self.filePath):
            if self.lief.libraries:
                for library in self.lief.libraries:
                    rows.append([
                        MACHO_LOAD_COMMAND_TYPES[library.command],
                        library.name,
                        hex(library.command_offset),
                        self.listVersionToDottedVersion(library.compatibility_version),
                        self.listVersionToDottedVersion(library.current_version),
                        "{0:<6} Bytes".format(library.size),
                        library.timestamp
                    ])
                self.log("info", "Dynamic libraries : ")
                self.log("table", dict(header=["Command", "Name", "Offset", "Compatibility version", "Current version", "Size", "Timestamp"],rows=rows))
            else:
                self.log("warning", "No dynamic library found")
        else:
            self.log("warning", "No dynamic library found")

    def symbols(self):
        if not self.__check_session():
            return
        rows = []
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
            self.log("table", dict(header=["Name", "Type", "Val", "Size", "Visibility", "isFun", "isStatic", "isVar"], rows=rows))
        else:
            self.log("warning", "No symbol found")

    def dlls(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_pe(self.filePath):
            for lib in self.lief.libraries:
                self.log("info", lib)
        else:
            self.log("error", "No DLL found")

    def imports(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_pe(self.filePath):
            for imp in self.lief.imports:
                self.log("info", "{0}".format(imp.name))
                for function in imp.entries:
                    self.log("item", "{0} : {1}".format(hex(function.iat_address), function.name))
        else:
            self.log("warning", "No import found")

    def format(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath):
            self.log("info", "Format : {0}".format(PE_EXE_FORMATS[self.lief.format]))
        else:
            self.log("warning", "No format found")

    def imphash(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath):
            self.log("info", "Imphash : {0}".format(lief.PE.get_imphash(self.lief)))
        else:
            self.log("warning", "No imphash found")

    def compileDate(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath):
            timestamp = self.lief.header.time_date_stamps
            date = datetime.utcfromtimestamp(timestamp).strftime("%b %d %Y at %H:%M:%S")
            self.log("info", "Compilation date : {0}".format(date))
        else:
            self.log("warning", "No compilation date found")

    def header(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_macho(self.filePath):
            rows.append([
                MACHO_CPU_TYPES[self.lief.header.cpu_type],
                MACHO_FILE_TYPES[self.lief.header.file_type],
                self.lief.header.nb_cmds,
                "{:<6} Bytes".format(self.lief.header.sizeof_cmds),
                ':'.join(MACHO_HEADER_FLAGS[flag] for flag in self.lief.header.flags_list)
            ])
            self.log("info", "MachO headers : ")
            self.log("table", dict(header=["CPU Type", "File Type", "Nb Cmds", "Size of Cmds", "Flags"], rows=rows))
        else:
            self.log("warning", "No header found")

    def codeSignature(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.has_code_signature:
                rows = []
                rows.append([
                    MACHO_LOAD_COMMAND_TYPES[self.lief.code_signature.command],
                    hex(self.lief.code_signature.command_offset),
                    "{:<6} Bytes".format(self.lief.code_signature.size),
                        hex(self.lief.code_signature.data_offset),
                    "{:<6} Bytes".format(self.lief.code_signature.data_size)
                ])
                self.log("info", "MachO code signature : ")
                self.log("table", dict(header=["Command", "Cmd offset", "Cmd size", "Data offset", "Date size"], rows=rows))
            else:
                self.log("warning", "No code signature found")
        else:
            self.log("warning", "No code signature found")


    def exportedFunctions(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.exported_functions:
                for function in self.lief.exported_functions:
                    self.log("info", function)
            else:
                self.log("warning", "No exported function found")
        else:
            self.log("warning", "No exported function found")

    def exportedSymbols(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.exported_symbols:
                rows = []
                for symbol in self.lief.exported_symbols:
                    rows.append([
                        symbol.name,
                        symbol.numberof_sections,
                        hex(symbol.value),
                        MACHO_SYMBOL_ORIGINS[symbol.origin]
                    ])
                self.log("info", "MachO exported symbols : ")
                self.log("table", dict(header=["Name", "Nb section(s)", "Value", "Origin"], rows=rows))
            else:
                self.log("warning", "No exported symbol found")
        else:
            self.log("warning", "No exported symbol found")

    def importedFunctions(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.imported_functions:
                for function in self.lief.imported_functions:
                    self.log("info", function)
            else:
                self.log("warning", "No imported function found")
        else:
            self.log("warning", "No imported function found")

    def importedSymbols(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.imported_symbols:
                rows = []
                for symbol in self.lief.imported_symbols:
                    rows.append([
                        symbol.name,
                        symbol.numberof_sections,
                        hex(symbol.value),
                        MACHO_SYMBOL_ORIGINS[symbol.origin]
                    ])
                self.log("info", "MachO imported symbols : ")
                self.log("table", dict(header=["Name", "Nb section(s)", "Value", "Origin"], rows=rows))
            else:
                self.log("warning", "No imported symbol found")
        else:
            self.log("warning", "No imported symbol found")

    def sourceVersion(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.has_source_version:
                self.log("info", "Source version : ")
                self.log("item", "{0:<10} : {1}".format("command", MACHO_LOAD_COMMAND_TYPES[self.lief.source_version.command]))
                self.log("item", "{0:<10} : {1}".format("Offset", hex(self.lief.source_version.command_offset)))
                self.log("item", "{0:<10} : {1} Bytes".format("size", self.lief.source_version.size))
                self.log("item", "{0:<10} : {1}".format("Version", self.listVersionToDottedVersion(self.lief.source_version.version)))
            else:
                self.log("warning", "No source version found")
        else:
            self.log("warning", "No source version found")

    def subFramework(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.has_sub_framework:
                self.log("info", "Sub-framework : ")
                self.log("item", "{0:<10} : {1}".format("Command", MACHO_LOAD_COMMAND_TYPES[self.lief.sub_framework.command]))
                self.log("item", "{0:<10} : {1}".format("Offset", hex(self.lief.sub_framework.command_offset)))
                self.log("item", "{0:<10} : {1} Bytes".format("Size", self.lief.sub_framework.size))
                self.log("item", "{0:<10} : {1}".format("Umbrella", self.lief.sub_framework.umbrella))
            else:
                self.log("warning", "No sub-framework found")
        else:
            self.log("warning", "No sub-framework found")

    def uuid(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.has_uuid:
                self.log("info", "Uuid : ")
                self.log("item", "{0:<10} : {1}".format("Command", MACHO_LOAD_COMMAND_TYPES[self.lief.uuid.command]))
                self.log("item", "{0:<10} : {1}".format("Offset", hex(self.lief.uuid.command_offset)))
                self.log("item", "{0:<10} : {1} Bytes".format("Size", self.lief.uuid.size))
                self.log("item", "{0:<10} : {1}".format("Uuid", self.listUuidToUuid(self.lief.uuid.uuid)))
            else:
                self.log("warning", "No uuid found")
        else:
            self.log("warning", "No uuid found")

    def dataInCode(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.has_data_in_code:
                self.log("info", "Data in code : ")
                self.log("item", "{0:<12} : {1}".format("Command", MACHO_LOAD_COMMAND_TYPES[self.lief.data_in_code.command]))
                self.log("item", "{0:<12} : {1}".format("Offset", hex(self.lief.data_in_code.command_offset)))
                self.log("item", "{0:<12} : {1} Bytes".format("Size", self.lief.data_in_code.size))
                self.log("item", "{0:<12} : {1}".format("Data Offset", hex(self.lief.data_in_code.data_offset)))
            else:
                self.log("warning", "No data in code found")
        else:
            self.log("warning", "No data in code found")

    def mainCommand(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath):
            if self.lief.has_main_command:
                self.log("info", "Main command : ")
                self.log("item", "{0:<12} : {1}".format("Command", MACHO_LOAD_COMMAND_TYPES[self.lief.main_command.command]))
                self.log("item", "{0:<12} : {1}".format("Offset", hex(self.lief.main_command.command_offset)))
                self.log("item", "{0:<12} : {1} Bytes".format("Size", self.lief.main_command.size))
                self.log("item", "{0:<12} : {1}".format("Entrypoint", hex(self.lief.main_command.entrypoint)))
                self.log("item", "{0:<12} : {1} Bytes".format("Stack size", self.lief.main_command.stack_size))
            else:
                self.log("warning", "No main command found")
        else:
            self.log("warning", "No main command found")

    def commands(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_macho(self.filePath):
            if self.lief.commands:
                for command in self.lief.commands:
                    rows.append([
                        MACHO_LOAD_COMMAND_TYPES[command.command],
                        "{0:<6} Bytes".format(command.size),
                        hex(command.command_offset),
                    ])
                self.log("table", dict(header=["Command", "Size", "Offset"], rows=rows))
            else:
                self.log("warning", "No command found")
        else:
            self.log("warning", "No command found")
   
    """Usefuls methods"""

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

    def listUuidToUuid(self, list):
        if not list:
            return None
        else:
            uuid = ""
            for index, elt in enumerate(list):
                uuid += str(hex(elt))[2:]
                if index == 3 or index == 5 or index == 7 or index == 9:
                    uuid += '-'
            return uuid

    def listVersionToDottedVersion(self, list):
        if not list:
            return None
        else:
            version = ""
            for index, elt in enumerate(list):
                if index == 0:
                    version += str(elt)
                else:
                    version += '.' + str(elt)
            return version

    """Binary type methods"""

    def pe(self):
        if not self.__check_session():
            return
        if not lief.is_pe(self.filePath):
            self.log("error", "Wrong binary type")
            self.log("info", "Expected filetype : PE")
        else:
            if self.args.sections:
                self.sections()
            elif self.args.entrypoint:
                self.entrypoint()
            elif self.args.dlls:
                self.dlls()
            elif self.args.imports:
                self.imports()
            elif self.args.architecture:
                self.architecture()
            elif self.args.format:
                self.format()
            elif self.args.type:
                self.type()
            elif self.args.imphash:
                self.imphash()
            elif self.args.compiledate:
                self.compileDate()

    def elf(self):
        if not self.__check_session():
            return
        if not lief.is_elf(self.filePath):
            self.log("error", "Wrong binary type")
            self.log("info", "Expected filtype : ELF")
        else:
            if self.args.segments:
                self.segments()
            elif self.args.sections:
                self.sections()
            elif self.args.type:
                self.type()
            elif self.args.entrypoint:
                self.entrypoint()
            elif self.args.architecture:
                self.architecture()
            elif self.args.interpreter:
                self.interpreter()
            elif self.args.dynamic:
                self.dynamic()
            elif self.args.symbols:
                self.symbols()
            elif self.args.entropy:
                self.entropy()

    def macho(self):
        if not self.__check_session():
            return
        if not lief.is_macho(self.filePath):
            self.log("error", "Wrong binary type")
            self.log("info", "Expected filtype : MachO")
        else:
            if self.args.header:
                self.header()
            elif self.args.entrypoint:
                self.entrypoint()
            elif self.args.architecture:
                self.architecture()
            elif self.args.type:
                self.type()
            elif self.args.codesignature:
                self.codeSignature()
            elif self.args.expfunctions:
                self.exportedFunctions()
            elif self.args.expsymbols:
                self.exportedSymbols()
            elif self.args.impfunctions:
                self.importedFunctions()
            elif self.args.impsymbols:
                self.importedSymbols()
            elif self.args.sections:
                self.sections()
            elif self.args.segments:
                self.segments()
            elif self.args.sourceversion:
                self.sourceVersion()
            elif self.args.subframework:
                self.subFramework()
            elif self.args.uuid:
                self.uuid()
            elif self.args.dataincode:
                self.dataInCode()
            elif self.args.maincommand:
                self.mainCommand()
            elif self.args.commands:
                self.commands()
            elif self.args.dynamic:
                self.dynamic()

    """Main method"""

    def run(self):
        super(Lief, self).run()
        if self.args is None:
            return
        if not HAVE_LIEF:
            self.log("error", "Missing dependency, install lief (pip3 install lief)")
            return
        if self.args.subname == "pe":
            self.pe()
        elif self.args.subname == "elf":
            self.elf()
        elif self.args.subname == "macho":
            self.macho()
        else:
            self.log("error", "At least one of the parameters is required")
            self.usage()
