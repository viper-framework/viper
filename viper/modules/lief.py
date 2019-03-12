# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.


import math, os.path, string, json
from os import access
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from datetime import datetime

try:
    import lief
    HAVE_LIEF = True
except:
    HAVE_LIEF = False

class Lief(Module):
    cmd         = "lief"
    description = "Parse and extract information from ELF, PE, MachO, DEX, OAT, ART and VDEX formats"
    authors     = ["Jordan Samhi"]

    def __init__(self):
        super(Lief, self).__init__()
        subparsers  = self.parser.add_subparsers(dest="subname")
        
        parser_pe = subparsers.add_parser("pe", help="Extract information from PE files")
        parser_pe.add_argument("-A", "--architecture",      action="store_true", help="Show PE architecture")
        parser_pe.add_argument("-b", "--debug",             action="store_true", help="Show PE debug information")
        parser_pe.add_argument("-c", "--compiledate",       action="store_true", help="Show PE date of compilation")
        parser_pe.add_argument("-C", "--richheader",        action="store_true", help="Show PE rich header")
        parser_pe.add_argument("-d", "--dlls",              action="store_true", help="Show PE imported dlls")
        parser_pe.add_argument("-D", "--datadirectories",   action="store_true", help="Show PE data directories")
        parser_pe.add_argument("-e", "--entrypoint",        action="store_true", help="Show PE entrypoint")
        parser_pe.add_argument("-f", "--format",            action="store_true", help="Show PE format")
        parser_pe.add_argument("-g", "--signature",         action="store_true", help="Show PE signature")
        parser_pe.add_argument("-G", "--dialogs",           action="store_true", help="Show PE dialogs box information")
        parser_pe.add_argument("-H", "--header",            action="store_true", help="Show PE header")
        parser_pe.add_argument("-i", "--imports",           action="store_true", help="Show PE imported functions and DLLs")
        parser_pe.add_argument("-I", "--impfunctions",      action="store_true", help="Show PE imported functions")
        parser_pe.add_argument("-j", "--expfunctions",      action="store_true", help="Show PE exported functions")
        parser_pe.add_argument("-l", "--loadconfiguration", action="store_true", help="Show PE load configuration")
        parser_pe.add_argument("-L", "--langs",             action="store_true", help="Show PE langs and sublangs used")
        parser_pe.add_argument("-m", "--imphash",           action="store_true", help="Show PE imported functions hash")
        parser_pe.add_argument("-M", "--manifest",          action="store_true", help="Show PE Manifest")
        parser_pe.add_argument("-o", "--dosheader",         action="store_true", help="Show PE DOS header")
        parser_pe.add_argument("-O", "--icons",             action="store_true", help="Show PE icons information")
        parser_pe.add_argument("-r", "--relocations",       action="store_true", help="Show PE relocations")
        parser_pe.add_argument("-R", "--resources",         action="store_true", help="Show PE resources")
        parser_pe.add_argument("-s", "--sections",          action="store_true", help="Show PE sections")
        parser_pe.add_argument("-t", "--type",              action="store_true", help="Show PE type")
        parser_pe.add_argument("-T", "--tls",               action="store_true", help="Show PE tls")
        parser_pe.add_argument("-u", "--dosstub",           action="store_true", help="Show PE DOS stub")
        parser_pe.add_argument("-x", "--extracticons",      nargs='?',           help="Extract icons to the given path (default : ./)", const="./", metavar="path")
        parser_pe.add_argument("-y", "--dynamic",           action="store_true", help="Show PE dynamic libraries")
        parser_pe.add_argument("-Y", "--resourcestypes",    action="store_true", help="Show PE types of resources")
        parser_pe.add_argument("--id",                      nargs=1, type=int,   help="Define an id for following commands : -x", metavar="id")

        parser_elf = subparsers.add_parser("elf", help="Extract information from ELF files")
        parser_elf.add_argument("-A", "--architecture", action="store_true", help="Show ELF architecture")
        parser_elf.add_argument("-d", "--dynamic",      action="store_true", help="Show ELF dynamic libraries")
        parser_elf.add_argument("-e", "--entrypoint",   action="store_true", help="Show ELF entrypoint")
        parser_elf.add_argument("-E", "--entropy",      action="store_true", help="Show ELF entropy")
        parser_elf.add_argument("-g", "--gnu_hash",     action="store_true", help="Show ELF GNU hash")
        parser_elf.add_argument("-H", "--header",       action="store_true", help="Show ELF header")
        parser_elf.add_argument("-i", "--interpreter",  action="store_true", help="Show ELF interpreter")
        parser_elf.add_argument("-I", "--impfunctions", action="store_true", help="Show ELF imported functions")
        parser_elf.add_argument("-j", "--expfunctions", action="store_true", help="Show ELF exported functions")
        parser_elf.add_argument("-n", "--notes",        action="store_true", help="Show ELF notes")
        parser_elf.add_argument("-s", "--sections",     action="store_true", help="Show ELF sections")
        parser_elf.add_argument("-S", "--segments",     action="store_true", help="Show ELF segments")
        parser_elf.add_argument("-t", "--type",         action="store_true", help="Show ELF type")
        parser_elf.add_argument("-w", "--write",        nargs=1,             help="Write binary into file", metavar="fileName")
        parser_elf.add_argument("-y", "--symbols",      action="store_true", help="Show ELF symbols")
        parser_elf.add_argument("-z", "--strip",        action="store_true", help="Strip ELF binary")

        parser_macho = subparsers.add_parser("macho", help="Extract information from MachO files")
        parser_macho.add_argument("-A", "--architecture",   action="store_true", help="Show MachO architecture")
        parser_macho.add_argument("-c", "--commands",       action="store_true", help="Show MachO commands")
        parser_macho.add_argument("-C", "--codesignature",  action="store_true", help="Show MachO code signature")
        parser_macho.add_argument("-d", "--dynamic",        action="store_true", help="Show MachO dynamic libraries")
        parser_macho.add_argument("-D", "--dataincode",     action="store_true", help="Show MachO data in code")
        parser_macho.add_argument("-e", "--entrypoint",     action="store_true", help="Show MachO entrypoint")
        parser_macho.add_argument("-f", "--subframework",   action="store_true", help="Show MachO sub-framework")
        parser_macho.add_argument("-H", "--header",         action="store_true", help="Show MachO header")
        parser_macho.add_argument("-I", "--impfunctions",   action="store_true", help="Show MachO imported functions")
        parser_macho.add_argument("-j", "--expfunctions",   action="store_true", help="Show MachO exported functions")
        parser_macho.add_argument("-k", "--expsymbols",     action="store_true", help="Show MachO exported symbols")
        parser_macho.add_argument("-m", "--maincommand",    action="store_true", help="Show MachO main command")
        parser_macho.add_argument("-q", "--impsymbols",     action="store_true", help="Show MachO imported symbols")
        parser_macho.add_argument("-s", "--sections",       action="store_true", help="Show MachO sections")
        parser_macho.add_argument("-S", "--segments",       action="store_true", help="Show MachO segments")
        parser_macho.add_argument("-t", "--type",           action="store_true", help="Show MachO type")
        parser_macho.add_argument("-u", "--uuid",           action="store_true", help="Show MachO uuid")
        parser_macho.add_argument("-v", "--sourceversion",  action="store_true", help="Show MachO source version")
        parser_macho.add_argument("-y", "--symbols",        action="store_true", help="Show MachO symbols")

        parser_oat = subparsers.add_parser("oat", help="Extract information from OAT files")
        parser_oat.add_argument("-c", "--classname",            nargs=1,             help="Full name of class (Lcom/android/...;). Used with --methods", metavar="fullname", type=str)
        parser_oat.add_argument("-C", "--classes",              action="store_true", help="Show OAT classes")
        parser_oat.add_argument("-d", "--dynamic",              action="store_true", help="Show OAT dynamic libraries")
        parser_oat.add_argument("-D", "--dynamicrelocations",   action="store_true", help="Strip OAT dynamic relocations")
        parser_oat.add_argument("-e", "--entrypoint",           action="store_true", help="Show OAT entrypoint")
        parser_oat.add_argument("-E", "--entropy",              action="store_true", help="Show OAT entropy")
        parser_oat.add_argument("-g", "--gnu_hash",             action="store_true", help="Show OAT GNU hash")
        parser_oat.add_argument("-H", "--header",               action="store_true", help="Show OAT header")
        parser_oat.add_argument("-i", "--interpreter",          action="store_true", help="Show OAT interpreter")
        parser_oat.add_argument("-I", "--impfunctions",         action="store_true", help="Show OAT imported functions")
        parser_oat.add_argument("-j", "--expfunctions",         action="store_true", help="Show OAT exported functions")
        parser_oat.add_argument("-J", "--dex2dexjsoninfos",     action="store_true", help="Show OAT dex2dex json information")
        parser_oat.add_argument("-m", "--methods",              action="store_true", help="Show OAT methods by class")
        parser_oat.add_argument("-n", "--name",                 nargs=1, type=str,   help="Define a name for the following commands : -m", metavar="name")
        parser_oat.add_argument("-N", "--notes",                action="store_true", help="Show OAT notes")
        parser_oat.add_argument("-s", "--sections",             action="store_true", help="Show OAT sections")
        parser_oat.add_argument("-S", "--segments",             action="store_true", help="Show OAT segments")
        parser_oat.add_argument("-t", "--type",                 action="store_true", help="Show OAT type")
        parser_oat.add_argument("-w", "--write",                nargs=1,             help="Write binary into file", metavar="fileName")
        parser_oat.add_argument("-y", "--symbols",              action="store_true", help="Show OAT symbols")
        parser_oat.add_argument("-z", "--strip",                action="store_true", help="Strip OAT binary")

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
        if lief.is_oat(self.filePath) or lief.is_elf(self.filePath):
            for section in self.lief.sections:
                rows.append([
                    section.name,
                    hex(section.offset),
                    hex(section.virtual_address),
                    "{0:<6} bytes".format(section.size),
                    self.liefConstToString(section.type),
                    ':'.join(self.liefConstToString(flag) for flag in section.flags_list),
                    round(section.entropy, 4)
                ])
            self.log("info", "ELF sections : ")
            self.log("table", dict(header=["Name", "Address", "RVA", "Size", "Type", "Flags", "Entropy"], rows=rows))

        elif lief.is_pe(self.filePath):
            for section in self.lief.sections:
                rows.append([
                    section.name,
                    hex(section.virtual_address),
                    "{0:<6} bytes".format(section.virtual_size),
                    hex(section.offset),
                    "{0:<6} bytes".format(section.size),
                    round(section.entropy, 4)
                ])
            self.log("info", "PE sections : ")
            self.log("table", dict(header=["Name","RVA", "VirtualSize", "PointerToRawData", "RawDataSize", "Entropy"], rows=rows))
        elif lief.is_macho(self.filePath):
            for section in self.lief.sections:
                rows.append([
                    section.name,
                    hex(section.virtual_address),
                    self.liefConstToString(section.type),
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
        if lief.is_oat(self.filePath) or lief.is_elf(self.filePath):
            for segment in self.lief.segments:
                flags = []
                if lief.ELF.SEGMENT_FLAGS.R in segment:
                    flags.append(self.liefConstToString(lief.ELF.SEGMENT_FLAGS.R))
                if lief.ELF.SEGMENT_FLAGS.W in segment:
                    flags.append(self.liefConstToString(lief.ELF.SEGMENT_FLAGS.W))
                if lief.ELF.SEGMENT_FLAGS.X in segment:
                    flags.append(self.liefConstToString(lief.ELF.SEGMENT_FLAGS.X))
                if lief.ELF.SEGMENT_FLAGS.NONE in segment:
                    flags.append(self.liefConstToString(lief.ELF.SEGMENT_FLAGS.NONE))
                rows.append([
                    self.liefConstToString(segment.type),
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
                self.log("item", "{0:<18} : {1} bytes".format("Size", segment.file_size)),
                self.log("item", "{0:<18} : {1}".format("Offset", segment.file_offset)),
                self.log("item", "{0:<18} : {1}".format("Command", self.liefConstToString(segment.command))),
                self.log("item", "{0:<18} : {1} bytes".format("Command size", segment.size)),
                self.log("item", "{0:<18} : {1}".format("Command offset", hex(segment.command_offset))),
                self.log("item", "{0:<18} : {1}".format("Number of sections", segment.numberof_sections)),
                self.log("item", "{0:<18} : {1}".format("Initial protection", segment.init_protection)),
                self.log("item", "{0:<18} : {1}".format("Maximum protection", segment.max_protection)),
                self.log("item", "{0:<18} : {1}".format("Virtual address", hex(segment.virtual_address))),
                self.log("item", "{0:<18} : {1} bytes".format("Virtual size", segment.virtual_size)),
                if segment.sections:
                    for section in segment.sections:
                        rows.append([
                            section.name,
                            hex(section.virtual_address),
                            self.liefConstToString(section.type),
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
        if lief.is_oat(self.filePath):
            self.log("info", "Type : {0}".format(self.liefConstToString(self.lief.type)))
        elif lief.is_elf(self.filePath):
            self.log("info", "Type : {0}".format(self.liefConstToString(self.lief.header.file_type)))
        elif lief.is_pe(self.filePath):
            self.log("info", "Type : {0}".format(self.liefConstToString(lief.PE.get_type(self.filePath))))
        elif lief.is_macho(self.filePath):
            self.log("info", "Type : {0}".format(self.liefConstToString(self.lief.header.file_type)))
        else:
            self.log("warning", "No type found")

    def entrypoint(self):
        if not self.__check_session():
            return
        if lief.is_oat(self.filePath):
            self.log("info", "Entrypoint : {0}".format(hex(self.lief.entrypoint)))
        elif lief.is_elf(self.filePath):
            self.log("info", "Entrypoint : {0}".format(hex(self.lief.header.entrypoint)))
        elif lief.is_pe(self.filePath):
            self.log("info", "Entrypoint : {0}".format(hex(self.lief.entrypoint)))
        elif lief.is_macho(self.filePath) and self.lief.has_entrypoint:
            self.log("info", "Entrypoint : {0}".format(hex(self.lief.entrypoint)))
        else:
            self.log("warning", "No entrypoint found")
    
    def architecture(self):
        if not self.__check_session():
            return
        if lief.is_elf(self.filePath):
            self.log("info", "Architecture : {0}".format(self.liefConstToString(self.lief.header.machine_type)))
        elif lief.is_pe(self.filePath):
            self.log("info", "Architecture : {0}".format(self.liefConstToString(self.lief.header.machine)))
        elif lief.is_macho(self.filePath):
            self.log("info", "Architecture : {0}".format(self.liefConstToString(self.lief.header.cpu_type)))
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
        if (lief.is_oat(self.filePath) and self.lief.has_interpreter) or (lief.is_elf(self.filePath) and self.lief.has_interpreter):
            self.log("info", "Interpreter : {0}".format(self.lief.interpreter))
        else:
            self.log("warning", "No interpreter found")

    def dynamic(self):
        if not self.__check_session():
            return
        rows = []
        if (lief.is_oat(self.filePath) or lief.is_elf(self.filePath) or lief.is_pe(self.filePath)) and self.lief.libraries:
            for lib in self.lief.libraries:
                self.log("info", lib)
        elif lief.is_macho(self.filePath) and self.lief.libraries:
            for library in self.lief.libraries:
                rows.append([
                    self.liefConstToString(library.command),
                    library.name,
                    hex(library.command_offset),
                    self.listVersionToDottedVersion(library.compatibility_version),
                    self.listVersionToDottedVersion(library.current_version),
                    "{0:<6} bytes".format(library.size),
                    library.timestamp
                ])
            self.log("info", "Dynamic libraries : ")
            self.log("table", dict(header=["Command", "Name", "Offset", "Compatibility version", "Current version", "Size", "Timestamp"],rows=rows))
        else:
            self.log("warning", "No dynamic library found")

    def symbols(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_oat(self.filePath) or lief.is_elf(self.filePath):
            for symbol in self.lief.symbols:
                rows.append([
                    symbol.name,
                    self.liefConstToString(symbol.type),
                    hex(symbol.value),
                    hex(symbol.size),
                    self.liefConstToString(symbol.visibility),
                    'X' if symbol.is_function else '-',
                    'X' if symbol.is_static else '-',
                    'X' if symbol.is_variable else '-'
                ])
            self.log("info", "ELF symbols : ")
            self.log("table", dict(header=["Name", "Type", "Val", "Size", "Visibility", "isFun", "isStatic", "isVar"], rows=rows))
        elif lief.is_macho(self.filePath) and self.lief.symbols:
            self.log("info", "MachO symbols : ")
            for symbol in self.lief.symbols:
                self.log("info", "Information of symbol : ")
                self.log("item", "{0:<19} : {1}".format("Name", symbol.name))
                self.log("item", "{0:<19} : {1}".format("description", hex(symbol.description)))
                self.log("item", "{0:<19} : {1}".format("Number of sections", symbol.numberof_sections))
                self.log("item", "{0:<19} : {1}".format("Type", hex(symbol.type)))
                self.log("item", "{0:<19} : {1}".format("Value", hex(symbol.value)))
                self.log("item", "{0:<19} : {1}".format("Origin", self.liefConstToString(symbol.origin)))
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
            self.log("info", "Format : {0}".format(self.liefConstToString(self.lief.format)))
        else:
            self.log("warning", "No format found")

    def imphash(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath):
            self.log("info", "Imphash : {0}".format(lief.PE.get_imphash(self.lief)))
        else:
            self.log("warning", "No imphash found")

    def gnu_hash(self):
        if not self.__check_session():
            return
        if (lief.is_oat(self.filePath) and self.lief.use_gnu_hash) or (lief.is_elf(self.filePath) and not lief.is_oat(self.filePath) and self.lief.gnu_hash):
            self.log("info", "GNU hash : ")
            self.log("item", "{0} : {1}".format("Number of buckets", self.lief.gnu_hash.nb_buckets))
            self.log("item", "{0} : {1}".format("First symbol index", hex(self.lief.gnu_hash.symbol_index)))
            self.log("item", "{0} : {1}".format("Bloom filters", ', '.join(str(hex(fil)) for fil in self.lief.gnu_hash.bloom_filters)))
            self.log("item", "{0} : {1}".format("Hash buckets", ', '.join(str(hex(bucket)) for bucket in self.lief.gnu_hash.buckets)))
            self.log("item", "{0} : {1}".format("Hash values", ', '.join(str(hex(h)) for h in self.lief.gnu_hash.hash_values)))
        else:
            self.log("warning", "No GNU hash found")

    def compileDate(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath):
            self.log("info", "Compilation date : {0}".format(self.fromTimestampToDate(self.lief.header.time_date_stamps)))
        else:
            self.log("warning", "No compilation date found")

    def strip(self):
        if not self.__check_session():
            return
        if lief.is_oat(self.filePath) or lief.is_elf(self.filePath):
            self.lief.strip()
            self.log("success", "The binary has been stripped")
            self.log("warning", "Do not forget --write (-w) option if you want your stripped binary to be saved")
        else:
            self.log("warning", "Binary must be of type ELF or OAT")

    def write(self):
        if not self.__check_session():
            return
        fileName = self.args.write[0]
        destFolder = './' if '/' not in fileName else fileName[:fileName.rfind('/')+1]
        if os.path.isfile(fileName):
            self.log("error", "File already exists")
        elif not os.access(destFolder, os.X_OK | os.W_OK):
            self.log("error", "Cannot write into folder : {0}".format(destFolder))
        elif fileName[len(fileName)-1] == '/':
            self.log("error", "Please enter a file name")
        else:
            self.lief.write(fileName)
            self.log("success", "File succesfully saved")

    def notes(self):
        if not self.__check_session():
            return
        if (lief.is_oat(self.filePath) or lief.is_elf(self.filePath)) and self.lief.has_notes:
            self.log("info", "Notes : ")
            for note in self.lief.notes:
                self.log("success", "Information of {0} note : ".format(note.name))
                self.log("item", "{0} : {1}".format("Name", note.name))
                self.log("item", "{0} : {1}".format("ABI", self.liefConstToString(note.abi)))
                self.log("item", "{0} : {1}".format("Description", ''.join(str(hex(desc))[2:] for desc in note.description)))
                self.log("item", "{0} : {1}".format("Type", self.liefConstToString(note.type)))
                self.log("item", "{0} : {1}".format("Version", self.listVersionToDottedVersion(note.version)))
        else:
            self.log("warning", "No note found")

    def header(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_oat(self.filePath):
            self.log("info", "OAT header : ")
            self.log("item", "{0:<37} : {1}".format("Checksum", hex(self.lief.header.checksum)))
            self.log("item", "{0:<37} : {1}".format("Executable offset", hex(self.lief.header.executable_offset)))
            self.log("item", "{0:<37} : {1}".format("I2c code bridge offset", hex(self.lief.header.i2c_code_bridge_offset)))
            self.log("item", "{0:<37} : {1}".format("I2c bridge offset", hex(self.lief.header.i2i_bridge_offset)))
            self.log("item", "{0:<37} : {1}".format("Image file location oat checksum", hex(self.lief.header.image_file_location_oat_checksum)))
            self.log("item", "{0:<37} : {1}".format("Image file location of data", hex(self.lief.header.image_file_location_oat_data_begin)))
            self.log("item", "{0:<37} : {1}".format("Image patch delta", self.lief.header.image_patch_delta))
            self.log("item", "{0:<37} : {1}".format("Insctruction set", self.liefConstToString(self.lief.header.instruction_set)))
            self.log("item", "{0:<37} : {1}".format("JNI DLSYM lookup offset", hex(self.lief.header.jni_dlsym_lookup_offset)))
            self.log("item", "{0:<37} : {1} bytes".format("Key value size", self.lief.header.key_value_size))
            self.log("item", "{0:<37} : {1}".format("Keys", ", ".join(self.liefConstToString(key) for key in self.lief.header.keys)))
            self.log("item", "{0:<37} : {1}".format("Magic", "{0} ({1})".format(' '.join(hex(m) for m in self.lief.header.magic), ''.join(chr(m) for index, m in enumerate(self.lief.header.magic) if index < 3))))
            self.log("item", "{0:<37} : {1}".format("Number of dex files", self.lief.header.nb_dex_files))
            self.log("item", "{0:<37} : {1}".format("Oat dex files offset", hex(self.lief.header.oat_dex_files_offset)))
            self.log("item", "{0:<37} : {1}".format("Quick generic JNI trampoline offset", hex(self.lief.header.quick_generic_jni_trampoline_offset)))
            self.log("item", "{0:<37} : {1}".format("Quick IMT conflict trampoline offset", hex(self.lief.header.quick_imt_conflict_trampoline_offset)))
            self.log("item", "{0:<37} : {1}".format("Quick resolution trampoline offset", hex(self.lief.header.quick_resolution_trampoline_offset)))
            self.log("item", "{0:<37} : {1}".format("Quick to interpreter bridge offset", hex(self.lief.header.quick_to_interpreter_bridge_offset)))
            self.log("item", "{0:<37} : {1}".format("Version", self.lief.header.version))
        elif lief.is_macho(self.filePath):
            self.log("info", "MachO header : ")
            self.log("item", "{0:<15} : {1}".format("CPU type", self.liefConstToString(self.lief.header.cpu_type)))
            self.log("item", "{0:<15} : {1}".format("File type", self.liefConstToString(self.lief.header.file_type)))
            self.log("item", "{0:<15} : {1}".format("Number of cmds", self.lief.header.nb_cmds))
            self.log("item", "{0:<15} : {1} bytes".format("Size of cmds", self.lief.header.sizeof_cmds))
            self.log("item", "{0:<15} : {1}".format("Flags", ':'.join(self.liefConstToString(flag) for flag in self.lief.header.flags_list)))
        elif lief.is_pe(self.filePath):
            self.log("info", "PE header : ")
            self.log("item", "{0:<28} : {1}".format("Type", self.liefConstToString(self.lief.header.machine)))
            self.log("item", "{0:<28} : {1}".format("Number of sections", self.lief.header.numberof_sections))
            self.log("item", "{0:<28} : {1}".format("Number of symbols", self.lief.header.numberof_symbols))
            self.log("item", "{0:<28} : {1}".format("Pointer to symbol table", hex(self.lief.header.pointerto_symbol_table)))
            self.log("item", "{0:<28} : {1}".format("Signature", "{0} ({1})".format(' '.join(hex(sig) for sig in self.lief.header.signature), ''.join(chr(sig) for sig in self.lief.header.signature))))
            self.log("item", "{0:<28} : {1}".format("Date of compilation", self.fromTimestampToDate(self.lief.header.time_date_stamps)))
            self.log("item", "{0:<28} : {1:<6} bytes".format("Size of optional header", self.lief.header.sizeof_optional_header))
            if self.lief.header.sizeof_optional_header > 0:
                self.log("success", "Optional header : ")
                self.log("item", "{0:<28} : {1}".format("Entrypoint", hex(self.lief.optional_header.addressof_entrypoint)))
                self.log("item", "{0:<28} : {1}".format("Base of code", hex(self.lief.optional_header.baseof_code)))
                self.log("item", "{0:<28} : {1}".format("Checksum", hex(self.lief.optional_header.checksum)))
                self.log("item", "{0:<28} : {1}".format("Base of image", hex(self.lief.optional_header.imagebase)))
                self.log("item", "{0:<28} : {1}".format("Magic", self.liefConstToString(self.lief.optional_header.magic)))
                self.log("item", "{0:<28} : {1}".format("Subsystem", self.liefConstToString(self.lief.optional_header.subsystem)))
                self.log("item", "{0:<28} : {1}".format("Min OS version", self.lief.optional_header.minor_operating_system_version))
                self.log("item", "{0:<28} : {1}".format("Max OS version", self.lief.optional_header.major_operating_system_version))
                self.log("item", "{0:<28} : {1}".format("Min Linker version", self.lief.optional_header.minor_linker_version))
                self.log("item", "{0:<28} : {1}".format("Max Linker version", self.lief.optional_header.major_linker_version))
                self.log("item", "{0:<28} : {1}".format("Min Image version", self.lief.optional_header.minor_image_version))
                self.log("item", "{0:<28} : {1}".format("Max Image version", self.lief.optional_header.major_image_version))
                self.log("item", "{0:<28} : {1:<8} bytes".format("Size of code", self.lief.optional_header.sizeof_code))
                self.log("item", "{0:<28} : {1:<8} bytes".format("Size of headers", self.lief.optional_header.sizeof_headers))
                self.log("item", "{0:<28} : {1:<8} bytes".format("Size of heap commited", self.lief.optional_header.sizeof_heap_commit))
                self.log("item", "{0:<28} : {1:<8} bytes".format("Size of heap reserved", self.lief.optional_header.sizeof_heap_reserve))
                self.log("item", "{0:<28} : {1:<8} bytes".format("Size of image", self.lief.optional_header.sizeof_image))
                self.log("item", "{0:<28} : {1:<8} bytes".format("Size of Initialized data", self.lief.optional_header.sizeof_initialized_data))
                self.log("item", "{0:<28} : {1:<8} bytes".format("Size of Uninitialized data", self.lief.optional_header.sizeof_uninitialized_data))
                self.log("item", "{0:<28} : {1:<8} bytes".format("Size of stack commited", self.lief.optional_header.sizeof_stack_commit))
                self.log("item", "{0:<28} : {1:<8} bytes".format("Size of stack reserved", self.lief.optional_header.sizeof_stack_reserve))
        elif lief.is_elf(self.filePath):
            self.log("info", "ELF header : ")
            self.log("item", "{0:<26} : {1}".format("Type", self.liefConstToString(self.lief.header.file_type)))
            self.log("item", "{0:<26} : {1}".format("Entrypoint", hex(self.lief.header.entrypoint)))
            self.log("item", "{0:<26} : {1} bytes".format("Header size", self.lief.header.header_size))
            self.log("item", "{0:<26} : {1}".format("Identity", "{0} ({1})".format(' '.join(hex(iden) for iden in self.lief.header.identity), ''.join(chr(iden) for index, iden in enumerate(self.lief.header.identity) if index < 4))))
            self.log("item", "{0:<26} : {1}".format("Endianness", self.liefConstToString(self.lief.header.identity_data)))
            self.log("item", "{0:<26} : {1}".format("Class", self.liefConstToString(self.lief.header.identity_class)))
            self.log("item", "{0:<26} : {1}".format("OS/ABI", self.liefConstToString(self.lief.header.identity_os_abi)))
            self.log("item", "{0:<26} : {1}".format("Version", self.liefConstToString(self.lief.header.identity_version)))
            self.log("item", "{0:<26} : {1}".format("Architecture", self.liefConstToString(self.lief.header.machine_type)))
            self.log("item", "{0:<26} : {1}".format("MIPS Flags", ':'.join(self.liefConstToString(flag) for flag in self.lief.header.mips_flags_list) if self.lief.header.mips_flags_list else "No flags"))
            self.log("item", "{0:<26} : {1}".format("Number of sections", self.lief.header.numberof_sections))
            self.log("item", "{0:<26} : {1}".format("Number of segments", self.lief.header.numberof_segments))
            self.log("item", "{0:<26} : {1}".format("Program header offet", hex(self.lief.header.program_header_offset)))
            self.log("item", "{0:<26} : {1} bytes".format("Program header size", self.lief.header.program_header_size))
            self.log("item", "{0:<26} : {1}".format("Section Header offset", hex(self.lief.header.section_header_offset)))
            self.log("item", "{0:<26} : {1} bytes".format("Section header size", self.lief.header.section_header_size))
        else:
            self.log("warning", "No header found")

    def codeSignature(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath) and self.lief.has_code_signature:
            rows = []
            rows.append([
                self.liefConstToString(self.lief.code_signature.command),
                hex(self.lief.code_signature.command_offset),
                "{:<6} bytes".format(self.lief.code_signature.size),
                hex(self.lief.code_signature.data_offset),
                "{:<6} bytes".format(self.lief.code_signature.data_size)
            ])
            self.log("info", "MachO code signature : ")
            self.log("table", dict(header=["Command", "Cmd offset", "Cmd size", "Data offset", "Date size"], rows=rows))
        else:
            self.log("warning", "No code signature found")


    def exportedFunctions(self):
        if not self.__check_session():
            return
        if (
                (lief.is_macho(self.filePath) and self.lief.exported_functions) or 
                (lief.is_oat(self.filePath) and self.lief.exported_functions) or
                (lief.is_elf(self.filePath) and self.lief.exported_functions) or 
                (lief.is_pe(self.filePath) and self.lief.exported_functions)
        ):
            self.log("info", "Exported functions : ")
            for function in self.lief.exported_functions:
                self.log("info", function)
        else:
            self.log("warning", "No exported function found")

    def exportedSymbols(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath) and self.lief.exported_symbols:
            rows = []
            for symbol in self.lief.exported_symbols:
                rows.append([
                    symbol.name,
                    symbol.numberof_sections,
                    hex(symbol.value),
                    self.liefConstToString(symbol.origin)
                ])
            self.log("info", "MachO exported symbols : ")
            self.log("table", dict(header=["Name", "Nb section(s)", "Value", "Origin"], rows=rows))
        else:
            self.log("warning", "No exported symbol found")

    def importedFunctions(self):
        if not self.__check_session():
            return
        if (
                (lief.is_macho(self.filePath) and self.lief.imported_functions) or 
                (lief.is_oat(self.filePath) and self.lief.imported_functions) or
                (lief.is_elf(self.filePath) and self.lief.imported_functions) or 
                (lief.is_pe(self.filePath) and self.lief.imported_functions)
        ):
            self.log("info", "Imported functions : ")
            for function in self.lief.imported_functions:
                self.log("info", function)
        else:
            self.log("warning", "No imported function found")

    def importedSymbols(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath) and self.lief.imported_symbols:
            rows = []
            for symbol in self.lief.imported_symbols:
                rows.append([
                    symbol.name,
                    symbol.numberof_sections,
                    hex(symbol.value),
                    self.liefConstToString(symbol.origin)
                ])
            self.log("info", "MachO imported symbols : ")
            self.log("table", dict(header=["Name", "Nb section(s)", "Value", "Origin"], rows=rows))
        else:
            self.log("warning", "No imported symbol found")

    def sourceVersion(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath) and self.lief.has_source_version:
            self.log("info", "Source version : ")
            self.log("item", "{0:<10} : {1}".format("command", self.liefConstToString(self.lief.source_version.command)))
            self.log("item", "{0:<10} : {1}".format("Offset", hex(self.lief.source_version.command_offset)))
            self.log("item", "{0:<10} : {1} bytes".format("size", self.lief.source_version.size))
            self.log("item", "{0:<10} : {1}".format("Version", self.listVersionToDottedVersion(self.lief.source_version.version)))
        else:
            self.log("warning", "No source version found")

    def subFramework(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath) and self.lief.has_sub_framework:
            self.log("info", "Sub-framework : ")
            self.log("item", "{0:<10} : {1}".format("Command", self.liefConstToString(self.lief.sub_framework.command)))
            self.log("item", "{0:<10} : {1}".format("Offset", hex(self.lief.sub_framework.command_offset)))
            self.log("item", "{0:<10} : {1} bytes".format("Size", self.lief.sub_framework.size))
            self.log("item", "{0:<10} : {1}".format("Umbrella", self.lief.sub_framework.umbrella))
        else:
            self.log("warning", "No sub-framework found")

    def uuid(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath) and self.lief.has_uuid:
            self.log("info", "Uuid : ")
            self.log("item", "{0:<10} : {1}".format("Command", self.liefConstToString(self.lief.uuid.command)))
            self.log("item", "{0:<10} : {1}".format("Offset", hex(self.lief.uuid.command_offset)))
            self.log("item", "{0:<10} : {1} bytes".format("Size", self.lief.uuid.size))
            self.log("item", "{0:<10} : {1}".format("Uuid", self.listUuidToUuid(self.lief.uuid.uuid)))
        else:
            self.log("warning", "No uuid found")

    def dataInCode(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath) and self.lief.has_data_in_code:
            self.log("info", "Data in code : ")
            self.log("item", "{0:<12} : {1}".format("Command", self.liefConstToString(self.lief.data_in_code.command)))
            self.log("item", "{0:<12} : {1}".format("Offset", hex(self.lief.data_in_code.command_offset)))
            self.log("item", "{0:<12} : {1} bytes".format("Size", self.lief.data_in_code.size))
            self.log("item", "{0:<12} : {1}".format("Data Offset", hex(self.lief.data_in_code.data_offset)))
        else:
            self.log("warning", "No data in code found")

    def mainCommand(self):
        if not self.__check_session():
            return
        if lief.is_macho(self.filePath) and self.lief.has_main_command:
            self.log("info", "Main command : ")
            self.log("item", "{0:<12} : {1}".format("Command", self.liefConstToString(self.lief.main_command.command)))
            self.log("item", "{0:<12} : {1}".format("Offset", hex(self.lief.main_command.command_offset)))
            self.log("item", "{0:<12} : {1} bytes".format("Size", self.lief.main_command.size))
            self.log("item", "{0:<12} : {1}".format("Entrypoint", hex(self.lief.main_command.entrypoint)))
            self.log("item", "{0:<12} : {1} bytes".format("Stack size", self.lief.main_command.stack_size))
        else:
            self.log("warning", "No main command found")

    def commands(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_macho(self.filePath) and self.lief.commands:
            for command in self.lief.commands:
                rows.append([
                    self.liefConstToString(command.command),
                    "{0:<6} bytes".format(command.size),
                    hex(command.command_offset),
                ])
            self.log("table", dict(header=["Command", "Size", "Offset"], rows=rows))
        else:
            self.log("warning", "No command found")

    def dosHeader(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath):
            self.log("info", "DOS header : ")
            self.log("item", "{0:<28} : {1}".format("Magic", hex(self.lief.dos_header.magic)))
            self.log("item", "{0:<28} : {1}".format("Address of new EXE header", hex(self.lief.dos_header.addressof_new_exeheader)))
            self.log("item", "{0:<28} : {1}".format("Address of relocation table", hex(self.lief.dos_header.addressof_relocation_table)))
            self.log("item", "{0:<28} : {1}".format("Checksum", hex(self.lief.dos_header.checksum)))
            self.log("item", "{0:<28} : {1}".format("File size in pages", self.lief.dos_header.file_size_in_pages))
            self.log("item", "{0:<28} : {1}".format("Header size in paragraphs", self.lief.dos_header.header_size_in_paragraphs))
            self.log("item", "{0:<28} : {1}".format("Initial IP", self.lief.dos_header.initial_ip))
            self.log("item", "{0:<28} : {1}".format("Initial relative CS", self.lief.dos_header.initial_relative_cs))
            self.log("item", "{0:<28} : {1}".format("Initial relative SS", self.lief.dos_header.initial_relative_ss))
            self.log("item", "{0:<28} : {1}".format("Initial SP", self.lief.dos_header.initial_sp))
            self.log("item", "{0:<28} : {1}".format("Maximum extra paragraphs", self.lief.dos_header.maximum_extra_paragraphs))
            self.log("item", "{0:<28} : {1}".format("Minimum extra paragraphs", self.lief.dos_header.minimum_extra_paragraphs))
            self.log("item", "{0:<28} : {1}".format("Number of relocation", self.lief.dos_header.numberof_relocation))
            self.log("item", "{0:<28} : {1}".format("OEM ID", self.lief.dos_header.oem_id))
            self.log("item", "{0:<28} : {1}".format("OEM Info", self.lief.dos_header.oem_info))
            self.log("item", "{0:<28} : {1}".format("Overlay number", self.lief.dos_header.overlay_number))
            self.log("item", "{0:<28} : {1}".format("Used bytes in last page", self.lief.dos_header.used_bytes_in_the_last_page))
        else:
            self.log("warning", "No DOS header found")

    def datadirectories(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_pe(self.filePath) and self.lief.data_directories:
            for datadirectory in self.lief.data_directories:
                rows.append([
                    hex(datadirectory.rva),
                    "{0:<7} bytes".format(datadirectory.size),
                    self.liefConstToString(datadirectory.type),
                    datadirectory.section.name if datadirectory.has_section else '-'
                ])
            self.log("info", "Data directories")
            self.log("table", dict(header=["RVA", "Size", "Type", "Section"], rows=rows))
        else:
            self.log("warning", "No data directory found")
    
    def dosStub(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath):
            rawDosStub = ''.join(chr(stub) if chr(stub) in string.printable.replace(string.whitespace, '') else '.' for stub in self.lief.dos_stub)
            printableDosStub = [rawDosStub[i:i+16] for i in range(0, len(rawDosStub), 16)]
            self.log("info", "{0}{1}".format('Dos stub : \n','\n'.join(printableDosStub)))
        else:
            self.log("warning", "No DOS stub found")
    
    def debug(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath) and self.lief.has_debug:
            self.log("info", "Debug information : ")
            self.log("item", "{0:<28} : {1}".format("Address of Raw data", hex(self.lief.debug.addressof_rawdata)))
            self.log("item", "{0:<28} : {1}".format("Minor version of debug data", self.lief.debug.minor_version))
            self.log("item", "{0:<28} : {1}".format("Major version of debug data", self.lief.debug.major_version))
            self.log("item", "{0:<28} : {1}".format("Pointer to raw data", hex(self.lief.debug.pointerto_rawdata)))
            self.log("item", "{0:<28} : {1} bytes".format("Size of data", self.lief.debug.sizeof_data))
            self.log("item", "{0:<28} : {1}".format("Data of data creation", self.fromTimestampToDate(self.lief.debug.timestamp)))
            self.log("item", "{0:<28} : {1}".format("Type of debug information", self.liefConstToString(self.lief.debug.type)))
            if self.lief.debug.has_code_view:
                self.log("item", "{0:<28} : {1}".format("Code view", self.liefConstToString(self.lief.debug.code_view.cv_signature)))
                if isinstance(self.lief.debug.code_view, lief.PE.CodeViewPDB):
                    self.log("item", "{0:<28} : {1}".format("Age", self.lief.debug.code_view.age))
                    self.log("item", "{0:<28} : {1}".format("Signature", ''.join(str(hex(sig))[2:] for sig in self.lief.debug.code_view.signature)))
                    self.log("item", "{0:<28} : {1}".format("Path", self.lief.debug.code_view.filename))
        else:
            self.log("warning", "No debug information found")

    def loadConfiguration(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath) and self.lief.has_configuration:
            self.log("info", "Load configuration : ")
            self.log("item", "{0:<33} : {1}".format("Version", self.liefConstToString(self.lief.load_configuration.version)))
            self.log("item", "{0:<33} : {1}".format("Characteristics", hex(self.lief.load_configuration.characteristics)))
            self.log("item", "{0:<33} : {1}".format("Timedatestamp", self.fromTimestampToDate(self.lief.load_configuration.timedatestamp)))
            self.log("item", "{0:<33} : {1}".format("Major version", self.lief.load_configuration.major_version))
            self.log("item", "{0:<33} : {1}".format("Minor version", self.lief.load_configuration.minor_version))
            self.log("item", "{0:<33} : {1}".format("Global flags clear", self.lief.load_configuration.global_flags_clear))
            self.log("item", "{0:<33} : {1}".format("Global flags set", self.lief.load_configuration.global_flags_set))
            self.log("item", "{0:<33} : {1}".format("Critical section default timeout", self.lief.load_configuration.critical_section_default_timeout))
            self.log("item", "{0:<33} : {1}".format("Decommit free block threshold", self.lief.load_configuration.decommit_free_block_threshold))
            self.log("item", "{0:<33} : {1}".format("Decommit total free threshold", self.lief.load_configuration.decommit_total_free_threshold))
            self.log("item", "{0:<33} : {1}".format("Lock prefix table", self.lief.load_configuration.lock_prefix_table))
            self.log("item", "{0:<33} : {1} bytes".format("Maximum allocation size", self.lief.load_configuration.maximum_allocation_size))
            self.log("item", "{0:<33} : {1}".format("Virtual memory threshold", self.lief.load_configuration.virtual_memory_threshold))
            self.log("item", "{0:<33} : {1}".format("Process affinity mask", self.lief.load_configuration.process_affinity_mask))
            self.log("item", "{0:<33} : {1}".format("Process heap flags", self.lief.load_configuration.process_heap_flags))
            self.log("item", "{0:<33} : {1}".format("CSD Version", self.lief.load_configuration.csd_version))
            self.log("item", "{0:<33} : {1}".format("Edit list", self.lief.load_configuration.editlist))
            self.log("item", "{0:<33} : {1}".format("Security cookie", hex(self.lief.load_configuration.security_cookie)))
        else:
            self.log("warning", "No load configuration found")

    def dex2dexJson(self):
        if not self.__check_session():
            return
        if lief.is_oat(self.filePath) and self.lief.dex2dex_json_info:
            dex2dexInfo = json.loads(self.lief.dex2dex_json_info)
            for fileName, descriptions in dex2dexInfo.items():
                self.log("info", "Dex file : {0}".format(fileName))
                for cl, _ in descriptions.items():
                    self.log("item", "{0} : {1}".format("Class", cl))
        else:
            self.log("warning", "No dex2dex json found")

    def dynamicRelocations(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_oat(self.filePath) and self.lief.dynamic_relocations:
            for dynamicRelocation in self.lief.dynamic_relocations:
                rows.append([
                    hex(dynamicRelocation.address),
                    self.liefConstToString(dynamicRelocation.purpose),
                    dynamicRelocation.section.name if dynamicRelocation.has_section else '-',
                    dynamicRelocation.symbol.name if dynamicRelocation.has_symbol else '-',
                    "{0:<5} bits".format(dynamicRelocation.size)
                ])
            self.log("info", "OAT dynamic relocations : ")
            self.log("table", dict(header=["Address", "Purpose", "Section", "Symbol", "Size"], rows=rows))
        else:
            self.log("warning", "No dynamic relocation found")

    def relocations(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_pe(self.filePath) and self.lief.has_relocations:
            for relocation in self.lief.relocations:
                for entry in relocation.entries:
                    rows.append([
                        hex(relocation.virtual_address),
                        self.liefConstToString(entry.type),
                        "{0:<6} bytes".format(entry.size),
                        hex(entry.position),
                        hex(entry.address),
                        hex(entry.data)
                    ])
            self.log("info", "PE relocations : ")
            self.log("table", dict(header=["Relocation Addr", "Entry type", "Entry size", "Entry position", "Entry address", "Entry data"], rows=rows))
        else:
            self.log("warning", "No relocation found")
   
    def resources(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath) and self.lief.has_resources:
            self.log("info", "PE resources : ")
            self.log("item", "{0:<17} : {1}".format("Name", self.lief.resources.name if self.lief.resources.has_name else "No name"))
            self.log("item", "{0:<17} : {1}".format("Number of childs", len(self.lief.resources.childs)))
            self.log("item", "{0:<17} : {1}".format("Depth", self.lief.resources.depth))
            self.log("item", "{0:<17} : {1}".format("Type", "Directory" if self.lief.resources.is_directory else "Data" if self.lief.resources.is_data else "Unknown"))
            self.log("item", "{0:<17} : {1}".format("Id", hex(self.lief.resources.id)))
        else:
            self.log("warning", "No resource found")

    def tls(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath) and self.lief.has_tls:
            self.log("info", "PE tls : ")
            self.log("item", "{0:<21} : {1}".format("Address of callbacks", hex(self.lief.tls.addressof_callbacks)))
            self.log("item", "{0:<21} : {1}".format("Address of index", hex(self.lief.tls.addressof_index)))
            self.log("item", "{0:<21} : {1}".format("Address of raw data", " - ".join(hex(addr) for addr in self.lief.tls.addressof_raw_data)))
            self.log("item", "{0:<21} : {1}".format("Callbacks", " - ".join(hex(callback) for callback in self.lief.tls.callbacks)))
            self.log("item", "{0:<21} : {1}".format("Characteristics", hex(self.lief.tls.characteristics)))
            self.log("item", "{0:<21} : {1}".format("Data template", self.lief.tls.data_template))
            self.log("item", "{0:<21} : {1}".format("Directory", self.liefConstToString(self.lief.tls.directory.type) if self.lief.tls.has_data_directory else '-'))
            self.log("item", "{0:<21} : {1}".format("Section", self.lief.tls.section.name if self.lief.tls.has_section else '-'))
            self.log("item", "{0:<21} : {1}".format("Size of zero fill", self.lief.tls.sizeof_zero_fill))
        else:
            self.log("warning", "No tls found")
    
    def richHeader(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_pe(self.filePath) and self.lief.has_rich_header:
            self.log("info", "Rich header key : {0}".format(hex(self.lief.rich_header.key)))
            self.log("info", "Rich header entries : ")
            for entry in self.lief.rich_header.entries:
                rows.append([
                    hex(entry.id),
                    entry.count,
                    hex(entry.build_id)
                ])
            self.log("table", dict(header=["ID", "Count", "Build ID"], rows=rows))
        else:
            self.log("warning", "No rich header found")
    
    def signature(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath) and self.lief.has_signature:
            self.log("info", "PE signature")
            self.log("item", "{0:<20} : {1}".format("Version", self.lief.signature.version))
            self.log("item", "{0:<20} : {1}".format("Digestion algorithm", lief.PE.oid_to_string(self.lief.signature.digest_algorithm)))
            self.log("success", "Content information")
            self.log("item", "{0:<20} : {1}".format("Content type", lief.PE.oid_to_string(self.lief.signature.content_info.content_type)))
            self.log("item", "{0:<20} : {1}".format("Digest", self.lief.signature.content_info.digest if self.lief.signature.content_info.digest else '-'))
            self.log("item", "{0:<20} : {1}".format("Digest algorithm", self.lief.signature.content_info.digest_algorithm if self.lief.signature.content_info.digest_algorithm else '-' ))
            self.log("success", "Certificates")
            for index, certificate in enumerate(self.lief.signature.certificates):
                self.log("info", "Certificate N°{0}".format(index+1))
                self.log("item", "{0:<20} : {1}".format("Version", certificate.version))
                self.log("item", "{0:<20} : {1}".format("Serial number", '.'.join(str(num) for num in certificate.serial_number)))
                self.log("item", "{0:<20} : {1}".format("Signature algorithm", lief.PE.oid_to_string(certificate.signature_algorithm)))
                self.log("item", "{0:<20} : {1}".format("Valid from", self.fromListOfDatetoDate(certificate.valid_from)))
                self.log("item", "{0:<20} : {1}".format("Valid to", self.fromListOfDatetoDate(certificate.valid_to)))
                self.log("item", "{0:<20} : {1}".format("Issuer", certificate.issuer))
                self.log("item", "{0:<20} : {1}".format("Subject", certificate.subject))
        else:
            self.log("warning", "No signature found")
    
    def manifest(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath) and self.lief.has_resources and self.lief.resources_manager.has_manifest:
            self.log("info", "PE manifest : \n{0}".format(self.lief.resources_manager.manifest))
        else:
            self.log("warning", "No manifest found")

    def resourcesTypes(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath) and self.lief.has_resources and self.lief.resources_manager.has_type:
            self.log("info", "Resources types availables : {0}".format(", ".join(self.liefConstToString(rType) for rType in self.lief.resources_manager.types_available)))
        else:
            self.log("warning", "No resources type found")

    def langs(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath) and self.lief.has_resources and self.lief.resources_manager.langs_available:
            self.log("info", "Langs availables      : {0}".format(", ".join(self.liefConstToString(lang) for lang in self.lief.resources_manager.langs_available)))
            self.log("info", "Sublangs availables   : {0}".format(", ".join(self.liefConstToString(sublang) for sublang in self.lief.resources_manager.sublangs_available)))
        else:
            self.log("warning", "No lang found")

    def icons(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_pe(self.filePath) and self.lief.has_resources and self.lief.resources_manager.has_icons:
            for icon in self.lief.resources_manager.icons:
                rows.append([
                    icon.id,
                    "{0} x {1}".format(icon.width, icon.height),
                    icon.bit_count,
                    icon.color_count,
                    self.liefConstToString(icon.lang),
                    self.liefConstToString(icon.sublang)
                    ])
            self.log("info", "PE icons : ")
            self.log("table", dict(header=["ID", "Size", "Bits/pixel", "Nb colors/icon", "Lang", "Sublang"], rows=rows))
        else:
            self.log("warning", "No icon found")

    def extractIcons(self):
        if not self.__check_session():
            return
        if lief.is_pe(self.filePath) and self.lief.has_resources and self.lief.resources_manager.has_icons:
            def iconProcessing(icon, destFolder):
                fileName = "{0}{1}_{2}.ico".format(destFolder, self.lief.name.replace('.', '_'), icon.id)
                if os.path.isfile(fileName):
                    self.log("error", "{0:<25} : {1}".format("File already exists", fileName))
                else:
                    icon.save(fileName)
                    self.log("success", "{0:<25} : {1}".format("File successfully saved", fileName))
            destFolder = self.args.extracticons
            if destFolder[len(destFolder)-1] != '/' : destFolder += '/'
            if not os.access(destFolder, os.X_OK | os.W_OK):
                self.log("error", "Cannot write into folder : {0}".format(destFolder))
            else:
                for icon in self.lief.resources_manager.icons:
                    if self.args.id:
                        if self.args.id[0] == icon.id:
                            iconProcessing(icon, destFolder)
                    else:
                        iconProcessing(icon, destFolder)
        else:
            self.log("warning", "No icon found")

    def dialogs(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_pe(self.filePath) and self.lief.has_resources and self.lief.resources_manager.has_dialogs:
            for index, dialog in enumerate(self.lief.resources_manager.dialogs):
                self.log("info", "Dialog N°{0}".format(index+1))
                self.log("item", "{0:<31} : {1}".format("Title", dialog.title if dialog.title else '-'))
                self.log("item", "{0:<31} : {1}".format("Version", dialog.version))
                self.log("item", "{0:<31} : {1:<5} px".format("Width of dialog", dialog.cx))
                self.log("item", "{0:<31} : {1:<5} px".format("Height of dialog", dialog.cy))
                self.log("item", "{0:<31} : {1}".format("Dialog box styles", ", ".join(self.liefConstToString(style) for style in dialog.dialogbox_style_list) if dialog.has_dialogbox_style else '-'))
                self.log("item", "{0:<31} : {1}".format("Window styles", ", ".join(self.liefConstToString(style) for style in dialog.style_list) if dialog.has_style else '-'))
                self.log("item", "{0:<31} : {1}".format("Help id", dialog.help_id))
                self.log("item", "{0:<31} : {1}".format("Lang", self.liefConstToString(dialog.lang)))
                self.log("item", "{0:<31} : {1}".format("Sublang", self.liefConstToString(dialog.sub_lang)))
                self.log("item", "{0:<31} : {1}".format("Signature", hex(dialog.signature)))
                self.log("item", "{0:<31} : {1}".format("Charset", dialog.charset))
                self.log("item", "{0:<31} : {1}".format("Typeface of font", dialog.typeface))
                self.log("item", "{0:<31} : {1}".format("Weight of font", dialog.weight))
                self.log("item", "{0:<31} : {1}".format("Point size of font", dialog.point_size))
                self.log("item", "{0:<31} : {1}".format("Upper-left corner x coordinate", dialog.x))
                self.log("item", "{0:<31} : {1}".format("Upper-left corner y coordinate", dialog.y))
                for item in dialog.items:
                    self.log("success", "Item in dialog N°{0} of id {1}".format(index+1, item.id))
                    self.log("item", "{0:<31} : {1}".format("Title", item.title))
                    self.log("item", "{0:<31} : {1:<5} px".format("Width of item", item.cx))
                    self.log("item", "{0:<31} : {1:<5} px".format("Height of item", item.cy))
                    self.log("item", "{0:<31} : {1}".format("Help id", item.help_id))
                    self.log("item", "{0:<31} : {1}".format("Upper-left corner x coordinate", item.x))
                    self.log("item", "{0:<31} : {1}".format("Upper-left corner y coordinate", item.y))
        else:
            self.log("warning", "No dialog found")

    def classes(self):
        if not self.__check_session():
            return
        rows = []
        if lief.is_oat(self.filePath) and self.lief.classes:
            for cl in self.lief.classes:
                rows.append([
                    cl.fullname,
                    cl.index,
                    len(cl.methods),
                    self.liefConstToString(cl.status),
                    self.liefConstToString(cl.type),
                ])
            self.log("info", "OAT classes : ")
            self.log("table", dict(header=["Name", "index", "Nb of methods", "Status", "Type"], rows=rows))
        else:
            self.log("warning", "No class found")

    def methods(self):
        if not self.__check_session():
            return
        def methodProcessing(method):
            self.log("info", "Information of method {0} : ".format(method.name))
            self.log("item", "{0:<17} : {1}".format("Name", method.name))
            self.log("item", "{0:<17} : {1}".format("Compiled", "Yes" if method.is_compiled else "No"))
            self.log("item", "{0:<17} : {1}".format("Dex optimization", "Yes" if method.is_dex2dex_optimized else "No"))
            self.log("item", "{0:<17} : {1}".format("Dex method", "Yes" if method.has_dex_method else "No"))
            self.log("item", "{0:<17} : {1}".format("Access flags", ' '.join(self.liefConstToString(flag) for flag in method.dex_method.access_flags) if method.has_dex_method else '-'))
            self.log("item", "{0:<17} : {1}".format("Offset", hex(method.dex_method.code_offset) if method.has_dex_method else '-'))
            self.log("item", "{0:<17} : {1}".format("Virtual method", '-' if not method.has_dex_method else "Yes" if method.dex_method.is_virtual else "No"))
            self.log("item", "{0:<17} : {1}".format("Parameters type", '-' if not method.has_dex_method else ", ".join(str(paramType) if not "PRIMITIVES" in str(paramType) else self.liefConstToString(paramType) for paramType in method.dex_method.prototype.parameters_type) if method.dex_method.prototype.parameters_type else '-'))
            self.log("item", "{0:<17} : {1}".format("Return type", '-' if not method.has_dex_method else ", ".join(str(returnType) if not "PRIMITIVES" in str(returnType) else self.liefConstToString(returnType) for returnType in method.dex_method.prototype.parameters_type) if method.dex_method.prototype.parameters_type else '-'))
        if lief.is_oat(self.filePath) and self.lief.methods:
            if self.args.classname:
                className = self.args.classname[0] + ';' if self.args.classname[0][len(self.args.classname[0])-1] != ';' else self.args.classname[0]
                classExists = False
                methodExists = False
                if self.lief.classes:
                    for index, cl in enumerate(self.lief.classes):
                        if cl.fullname == className:
                            classExists = True
                            if cl.methods:
                                for method in cl.methods:
                                    if self.args.name:
                                        if self.args.name[0] == method.name:
                                            methodExists = True
                                            methodProcessing(method)
                                    else:
                                        methodProcessing(method)
                                if self.args.name and not methodExists:
                                    self.log("error", "Method does not exist in this class")
                            else:
                                self.log("warning", "No method found")
                    if not classExists:
                        self.log("error", "This class does not exist (lief oat -C to see all classes)")
                else:
                    self.log("warning", "No class found")
            else:
                self.log("error", "A class name must be set (-c)")
        else:
            self.log("warning", "No method found")

    """Usefuls methods"""

    def liefConstToString(self, const):
        return str(const).split('.')[1]

    def fromTimestampToDate(self, timestamp):
        return datetime.utcfromtimestamp(timestamp).strftime("%b %d %Y at %H:%M:%S")

    def fromListOfDatetoDate(self, dateList):
        """Format of list : [Y, m, d, H, M, s]"""
        if not dateList:
            return None
        dateString = '-'.join(str(value) for value in dateList)
        timestamp = datetime.strptime(dateString, "%Y-%m-%d-%H-%M-%S").timestamp()
        return self.fromTimestampToDate(timestamp)

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

    def listUuidToUuid(self, listUuid):
        if not listUuid:
            return None
        else:
            uuid = ""
            for index, elt in enumerate(listUuid):
                uuid += str(hex(elt))[2:]
                if index == 3 or index == 5 or index == 7 or index == 9:
                    uuid += '-'
            return uuid

    def listVersionToDottedVersion(self, listVersion):
        if not listVersion:
            return None
        else:
            version = ""
            for index, elt in enumerate(listVersion):
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
            elif self.args.loadconfiguration:
                self.loadConfiguration()
            elif self.args.richheader:
                self.richHeader()
            elif self.args.dosstub:
                self.dosStub()
            elif self.args.dlls:
                self.dlls()
            elif self.args.imports:
                self.imports()
            elif self.args.architecture:
                self.architecture()
            elif self.args.format:
                self.format()
            elif self.args.header:
                self.header()
            elif self.args.type:
                self.type()
            elif self.args.imphash:
                self.imphash()
            elif self.args.compiledate:
                self.compileDate()
            elif self.args.dosheader:
                self.dosHeader()
            elif self.args.datadirectories:
                self.datadirectories()
            elif self.args.debug:
                self.debug()
            elif self.args.expfunctions:
                self.exportedFunctions()
            elif self.args.impfunctions:
                self.importedFunctions()
            elif self.args.dynamic:
                self.dynamic()
            elif self.args.relocations:
                self.relocations()
            elif self.args.resources:
                self.resources()
            elif self.args.tls:
                self.tls()
            elif self.args.signature:
                self.signature()
            elif self.args.manifest:
                self.manifest()
            elif self.args.resourcestypes:
                self.resourcesTypes()
            elif self.args.langs:
                self.langs()
            elif self.args.icons:
                self.icons()
            elif self.args.dialogs:
                self.dialogs()
            elif self.args.extracticons:
                self.extractIcons()

    def elf(self):
        if not self.__check_session():
            return
        if not lief.is_elf(self.filePath) or lief.is_oat(self.filePath):
            self.log("error", "Wrong binary type")
            self.log("info", "Expected filtype : ELF")
        else:
            if self.args.segments:
                self.segments()
            elif self.args.sections:
                self.sections()
            elif self.args.impfunctions:
                self.importedFunctions()
            elif self.args.write:
                self.write()
            elif self.args.type:
                self.type()
            elif self.args.strip:
                self.strip()
            elif self.args.gnu_hash:
                self.gnu_hash()
            elif self.args.entrypoint:
                self.entrypoint()
            elif self.args.architecture:
                self.architecture()
            elif self.args.interpreter:
                self.interpreter()
            elif self.args.dynamic:
                self.dynamic()
            elif self.args.notes:
                self.notes()
            elif self.args.symbols:
                self.symbols()
            elif self.args.entropy:
                self.entropy()
            elif self.args.expfunctions:
                self.exportedFunctions()
            elif self.args.header:
                self.header()

    def oat(self):
        if not self.__check_session():
            return
        if not lief.is_oat(self.filePath):
            self.log("error", "Wrong binary type")
            self.log("info", "Expected filtype : OAT")
        else:
            if self.args.segments:
                self.segments()
            elif self.args.sections:
                self.sections()
            elif self.args.impfunctions:
                self.importedFunctions()
            elif self.args.write:
                self.write()
            elif self.args.classes:
                self.classes()
            elif self.args.methods:
                self.methods()
            elif self.args.type:
                self.type()
            elif self.args.dex2dexjsoninfos:
                self.dex2dexJson()
            elif self.args.strip:
                self.strip()
            elif self.args.gnu_hash:
                self.gnu_hash()
            elif self.args.entrypoint:
                self.entrypoint()
            elif self.args.interpreter:
                self.interpreter()
            elif self.args.dynamic:
                self.dynamic()
            elif self.args.notes:
                self.notes()
            elif self.args.symbols:
                self.symbols()
            elif self.args.entropy:
                self.entropy()
            elif self.args.expfunctions:
                self.exportedFunctions()
            elif self.args.header:
                self.header()
            elif self.args.dynamicrelocations:
                self.dynamicRelocations()

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
            elif self.args.symbols:
                self.symbols()
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
        elif self.args.subname == "oat":
            self.oat()
        else:
            self.log("error", "At least one of the parameters is required")
            self.usage()
