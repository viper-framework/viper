# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import math
import os.path
import string
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from datetime import datetime

try:
    import lief
    HAVE_LIEF = True
except Exception:
    HAVE_LIEF = False


class Lief(Module):
    cmd = "lief"
    description = "Parse and extract information from ELF, PE, MachO, DEX, OAT, ART and VDEX formats"
    authors = ["Jordan Samhi"]

    def __init__(self):
        super(Lief, self).__init__()
        subparsers = self.parser.add_subparsers(dest="subname")

        """ Constants """

        self.IS_PE = False
        self.IS_ELF = False
        self.IS_MACHO = False
        self.IS_OAT = False
        self.IS_DEX = False
        self.IS_VDEX = False
        self.IS_ART = False
        self.FILE_PATH = None

        """ Arguments parsers """

        parser_pe = subparsers.add_parser("pe", help="Extract information from PE files")
        parser_pe.add_argument("-A", "--architecture", action="store_true", help="Show PE architecture")
        parser_pe.add_argument("-b", "--debug", action="store_true", help="Show PE debug information")
        parser_pe.add_argument("-c", "--compiledate", action="store_true", help="Show PE date of compilation")
        parser_pe.add_argument("-C", "--richheader", action="store_true", help="Show PE rich header")
        parser_pe.add_argument("-d", "--dlls", action="store_true", help="Show PE imported dlls")
        parser_pe.add_argument("-D", "--datadirectories", action="store_true", help="Show PE data directories")
        parser_pe.add_argument("-e", "--entrypoint", action="store_true", help="Show PE entrypoint")
        parser_pe.add_argument("-g", "--signature", action="store_true", help="Show PE signature")
        parser_pe.add_argument("-G", "--dialogs", action="store_true", help="Show PE dialogs box information")
        parser_pe.add_argument("-H", "--header", action="store_true", help="Show PE header")
        parser_pe.add_argument("-i", "--imports", action="store_true", help="Show PE imported functions and DLLs")
        parser_pe.add_argument("-I", "--impfunctions", action="store_true", help="Show PE imported functions")
        parser_pe.add_argument("-j", "--expfunctions", action="store_true", help="Show PE exported functions")
        parser_pe.add_argument("-l", "--loadconfiguration", action="store_true", help="Show PE load configuration")
        parser_pe.add_argument("-L", "--langs", action="store_true", help="Show PE langs and sublangs used")
        parser_pe.add_argument("-m", "--imphash", action="store_true", help="Show PE imported functions hash")
        parser_pe.add_argument("-M", "--manifest", action="store_true", help="Show PE Manifest")
        parser_pe.add_argument("-o", "--dosheader", action="store_true", help="Show PE DOS header")
        parser_pe.add_argument("-O", "--icons", action="store_true", help="Show PE icons information")
        parser_pe.add_argument("-r", "--relocations", action="store_true", help="Show PE relocations")
        parser_pe.add_argument("-R", "--resources", action="store_true", help="Show PE resources")
        parser_pe.add_argument("-s", "--sections", action="store_true", help="Show PE sections")
        parser_pe.add_argument("-t", "--type", action="store_true", help="Show PE type")
        parser_pe.add_argument("-T", "--tls", action="store_true", help="Show PE tls")
        parser_pe.add_argument("-u", "--dosstub", action="store_true", help="Show PE DOS stub")
        parser_pe.add_argument("-x", "--extracticons", nargs='?', help="Extract icons to the given path (default : ./)", const="./", metavar="path")
        parser_pe.add_argument("-y", "--dynamic", action="store_true", help="Show PE dynamic libraries")
        parser_pe.add_argument("-Y", "--resourcestypes", action="store_true", help="Show PE types of resources")
        parser_pe.add_argument("--id", nargs=1, type=int, help="Define an id for following commands : -x", metavar="id")

        parser_elf = subparsers.add_parser("elf", help="Extract information from ELF files")
        parser_elf.add_argument("-A", "--architecture", action="store_true", help="Show ELF architecture")
        parser_elf.add_argument("-b", "--impsymbols", action="store_true", help="Show ELF imported symbols")
        parser_elf.add_argument("-B", "--staticsymbols", action="store_true", help="Show ELF static symbols")
        parser_elf.add_argument("-d", "--dynamic", action="store_true", help="Show ELF dynamic libraries")
        parser_elf.add_argument("-e", "--entrypoint", action="store_true", help="Show ELF entrypoint")
        parser_elf.add_argument("-E", "--entropy", action="store_true", help="Show ELF entropy")
        parser_elf.add_argument("-g", "--gnu_hash", action="store_true", help="Show ELF GNU hash")
        parser_elf.add_argument("-H", "--header", action="store_true", help="Show ELF header")
        parser_elf.add_argument("-i", "--interpreter", action="store_true", help="Show ELF interpreter")
        parser_elf.add_argument("-I", "--impfunctions", action="store_true", help="Show ELF imported functions")
        parser_elf.add_argument("-j", "--expfunctions", action="store_true", help="Show ELF exported functions")
        parser_elf.add_argument("-k", "--expsymbols", action="store_true", help="Show ELF exported symbols")
        parser_elf.add_argument("-n", "--notes", action="store_true", help="Show ELF notes")
        parser_elf.add_argument("-o", "--objectrelocations", action="store_true", help="Show ELF object relocations")
        parser_elf.add_argument("-r", "--relocations", action="store_true", help="Show ELF relocations")
        parser_elf.add_argument("-s", "--sections", action="store_true", help="Show ELF sections")
        parser_elf.add_argument("-S", "--segments", action="store_true", help="Show ELF segments")
        parser_elf.add_argument("-t", "--type", action="store_true", help="Show ELF type")
        parser_elf.add_argument("-T", "--dynamicentries", action="store_true", help="Strip ELF dynamic entries")
        parser_elf.add_argument("-w", "--write", nargs=1, help="Write binary into file", metavar="fileName")
        parser_elf.add_argument("-y", "--symbols", action="store_true", help="Show ELF symbols")
        parser_elf.add_argument("-Y", "--dynamicsymbols", action="store_true", help="Show ELF dynamic symbols")
        parser_elf.add_argument("-z", "--strip", action="store_true", help="Strip ELF binary")

        parser_macho = subparsers.add_parser("macho", help="Extract information from MachO files")
        parser_macho.add_argument("-A", "--architecture", action="store_true", help="Show MachO architecture")
        parser_macho.add_argument("-c", "--commands", action="store_true", help="Show MachO commands")
        parser_macho.add_argument("-C", "--codesignature", action="store_true", help="Show MachO code signature")
        parser_macho.add_argument("-d", "--dynamic", action="store_true", help="Show MachO dynamic libraries")
        parser_macho.add_argument("-D", "--dataincode", action="store_true", help="Show MachO data in code")
        parser_macho.add_argument("-e", "--entrypoint", action="store_true", help="Show MachO entrypoint")
        parser_macho.add_argument("-f", "--subframework", action="store_true", help="Show MachO sub-framework")
        parser_macho.add_argument("-H", "--header", action="store_true", help="Show MachO header")
        parser_macho.add_argument("-I", "--impfunctions", action="store_true", help="Show MachO imported functions")
        parser_macho.add_argument("-j", "--expfunctions", action="store_true", help="Show MachO exported functions")
        parser_macho.add_argument("-k", "--expsymbols", action="store_true", help="Show MachO exported symbols")
        parser_macho.add_argument("-m", "--maincommand", action="store_true", help="Show MachO main command")
        parser_macho.add_argument("-q", "--impsymbols", action="store_true", help="Show MachO imported symbols")
        parser_macho.add_argument("-s", "--sections", action="store_true", help="Show MachO sections")
        parser_macho.add_argument("-S", "--segments", action="store_true", help="Show MachO segments")
        parser_macho.add_argument("-t", "--type", action="store_true", help="Show MachO type")
        parser_macho.add_argument("-u", "--uuid", action="store_true", help="Show MachO uuid")
        parser_macho.add_argument("-v", "--sourceversion", action="store_true", help="Show MachO source version")
        parser_macho.add_argument("-y", "--symbols", action="store_true", help="Show MachO symbols")

        parser_oat = subparsers.add_parser("oat", help="Extract information from OAT files")
        parser_oat.add_argument("-c", "--classname", nargs=1, help="Full name of class (com.android.etc...). Used with -m", metavar="fullname", type=str)
        parser_oat.add_argument("-C", "--classes", action="store_true", help="Show OAT classes")
        parser_oat.add_argument("-b", "--impsymbols", action="store_true", help="Show OAT imported symbols")
        parser_oat.add_argument("-B", "--staticsymbols", action="store_true", help="Show OAT static symbols")
        parser_oat.add_argument("-d", "--dynamic", action="store_true", help="Show OAT dynamic libraries")
        parser_oat.add_argument("-D", "--dynamicrelocations", action="store_true", help="Show OAT dynamic relocations")
        parser_oat.add_argument("-e", "--entrypoint", action="store_true", help="Show OAT entrypoint")
        parser_oat.add_argument("-E", "--entropy", action="store_true", help="Show OAT entropy")
        parser_oat.add_argument("-f", "--dexfiles", action="store_true", help="Show OAT dex files")
        parser_oat.add_argument("-g", "--gnu_hash", action="store_true", help="Show OAT GNU hash")
        parser_oat.add_argument("-H", "--header", action="store_true", help="Show OAT header")
        parser_oat.add_argument("-i", "--interpreter", action="store_true", help="Show OAT interpreter")
        parser_oat.add_argument("-I", "--impfunctions", action="store_true", help="Show OAT imported functions")
        parser_oat.add_argument("-j", "--expfunctions", action="store_true", help="Show OAT exported functions")
        parser_oat.add_argument("-k", "--expsymbols", action="store_true", help="Show OAT exported symbols")
        parser_oat.add_argument("-m", "--methods", action="store_true", help="Show OAT methods by class")
        parser_oat.add_argument("-n", "--name", nargs=1, type=str, help="Define a name for the following commands : -m, -x", metavar="name")
        parser_oat.add_argument("-N", "--notes", action="store_true", help="Show OAT notes")
        parser_oat.add_argument("-o", "--objectrelocations", action="store_true", help="Show OAT object relocations")
        parser_oat.add_argument("-r", "--relocations", action="store_true", help="Show OAT relocations")
        parser_oat.add_argument("-s", "--sections", action="store_true", help="Show OAT sections")
        parser_oat.add_argument("-S", "--segments", action="store_true", help="Show OAT segments")
        parser_oat.add_argument("-t", "--type", action="store_true", help="Show OAT type")
        parser_oat.add_argument("-T", "--dynamicentries", action="store_true", help="Show OAT dynamic entries")
        parser_oat.add_argument("-v", "--androidversion", action="store_true", help="Show OAT android version")
        parser_oat.add_argument("-w", "--write", nargs=1, help="Write binary into file", metavar="fileName")
        parser_oat.add_argument("-x", "--extractdexfiles", nargs='?', help="Extract dex files to the given path (default : ./)", const="./", metavar="path")
        parser_oat.add_argument("-y", "--symbols", action="store_true", help="Show OAT static and dynamic symbols")
        parser_oat.add_argument("-Y", "--dynamicsymbols", action="store_true", help="Show OAT dynamic symbols")
        parser_oat.add_argument("-z", "--strip", action="store_true", help="Strip OAT binary")

        parser_dex = subparsers.add_parser("dex", help="Extract information from DEX files")
        parser_dex.add_argument("-c", "--classname", nargs=1, help="Full name of class (com.android.etc...). Used with -m", metavar="fullname", type=str)
        parser_dex.add_argument("-C", "--classes", action="store_true", help="Show DEX classes")
        parser_dex.add_argument("-H", "--header", action="store_true", help="Show DEX header")
        parser_dex.add_argument("-m", "--methods", action="store_true", help="Show DEX methods by class")
        parser_dex.add_argument("-M", "--map", action="store_true", help="Show DEX map items")
        parser_dex.add_argument("-n", "--name", nargs=1, type=str, help="Define a name for the following commands : -m", metavar="name")
        parser_dex.add_argument("-s", "--strings", action="store_true", help="Show DEX strings")

        parser_vdex = subparsers.add_parser("vdex", help="Extract information from VDEX files")
        parser_vdex.add_argument("-f", "--dexfiles", action="store_true", help="Show VDEX dex files")
        parser_vdex.add_argument("-H", "--header", action="store_true", help="Show VDEX header")
        parser_vdex.add_argument("-n", "--name", nargs=1, type=str, help="Define a name for the following commands : -x", metavar="name")
        parser_vdex.add_argument("-v", "--androidversion", action="store_true", help="Show VDEX android version")
        parser_vdex.add_argument("-x", "--extractdexfiles", nargs='?', help="Extract dex files to the given path (default : ./)", const="./", metavar="path")

        parser_art = subparsers.add_parser("art", help="Extract information from ART files")
        parser_art.add_argument("-H", "--header", action="store_true", help="Show ART header")
        parser_art.add_argument("-v", "--androidversion", action="store_true", help="Show ART android version")

        self.lief = None

    def __check_session(self):
        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            return False
        if not self.lief:
            try:
                self.lief = self.parseBinary(__sessions__.current.file.path)
                self.FILE_PATH = __sessions__.current.file.path
            except lief.parser_error as e:
                self.log("error", "Unable to parse file : {0}".format(e))
                return False
        return True

    """Binaries methods"""

    def sections(self):
        """
           Display sections of ELF, PE, Mach-O and OAT formats
        """
        if not self.__check_session():
            return
        rows = []
        if self.IS_OAT or self.IS_ELF:
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
            self.log("info", "Sections : ")
            self.log("table", dict(header=["Name", "Address", "RVA", "Size", "Type", "Flags", "Entropy"], rows=rows))
        elif self.IS_PE:
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
            self.log("table", dict(header=["Name", "RVA", "VirtualSize", "PointerToRawData", "RawDataSize", "Entropy"], rows=rows))
        elif self.IS_MACHO:
            for section in self.lief.sections:
                rows.append([
                    section.name,
                    hex(section.virtual_address),
                    self.liefConstToString(section.type),
                    "{:<6} bytes".format(section.size),
                    hex(section.offset),
                    round(section.entropy, 4)
                ])
            self.log("info", "MachO sections : ")
            self.log("table", dict(header=["Name", "Virt Addr", "Type", "Size", "Offset", "Entropy"], rows=rows))
        else:
            self.log("warning", "No section found")
            return

    def segments(self):
        """
            Display segments of ELF, Mach-O and OAT formats
        """
        if not self.__check_session():
            return
        rows = []
        if self.IS_OAT or self.IS_ELF:
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
                    ':'.join(flags),
                    self.getEntropy(bytes(segment.content))
                ])
            self.log("info", "Segments : ")
            self.log("table", dict(header=["Type", "PhysicalAddress", "FileSize", "VirtuAddr", "MemSize", "Flags", "Entropy"], rows=rows))
        elif self.IS_MACHO:
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
                            round(section.entropy, 4)
                        ])
                    self.log("success", "Sections in segment {0} : ".format(segment.name))
                    self.log("table", dict(header=["Name", "Virtual address", "Type", "Size", "Offset", "Entropy"], rows=rows))
                    rows = []
        else:
            self.log("warning", "No segment found")

    def type(self):
        """
            Display type of ELF, PE, Mach-O and OAT formats
        """
        if not self.__check_session():
            return
        binaryType = None
        if self.IS_OAT:
            binaryType = self.lief.type
        elif self.IS_ELF:
            binaryType = self.lief.header.file_type
        elif self.IS_PE:
            binaryType = lief.PE.get_type(self.FILE_PATH)
        elif self.IS_MACHO:
            binaryType = self.lief.header.file_type
        if binaryType:
            self.log("info", "Type : {0}".format(self.liefConstToString(binaryType)))
        else:
            self.log("warning", "No type found")

    def entrypoint(self):
        """
            Display entrypoint of ELF, PE, Mach-O and OAT formats
        """
        if not self.__check_session():
            return
        entrypoint = None
        if self.IS_OAT:
            entrypoint = self.lief.entrypoint
        elif self.IS_ELF:
            entrypoint = self.lief.header.entrypoint
        elif self.IS_PE:
            entrypoint = self.lief.entrypoint
        elif self.IS_MACHO and self.lief.has_entrypoint:
            entrypoint = self.lief.entrypoint
        if entrypoint:
            self.log("info", "Entrypoint : {0}".format(hex(entrypoint)))
        else:
            self.log("warning", "No entrypoint found")

    def architecture(self):
        """
            Display architecture type of ELF, PE and Mach-O formats
        """
        if not self.__check_session():
            return
        architecture = None
        if self.IS_ELF:
            architecture = self.lief.header.machine_type
        elif self.IS_PE:
            architecture = self.lief.header.machine
        elif self.IS_MACHO:
            architecture = self.lief.header.cpu_type
        if architecture:
            self.log("info", "Architecture : {0}".format(self.liefConstToString(architecture)))
        else:
            self.log("warning", "No architecture found")

    def entropy(self):
        """
            Display entropy of a binary file
        """
        if not self.__check_session():
            return
        entropy = self.getEntropy(bytes(__sessions__.current.file.data))
        self.log("info", "Entropy : {0}".format(str(entropy)))
        if entropy > 7:
            self.log("warning", "The binary is probably packed")

    def interpreter(self):
        """
            Display interpreter of ELF and OAT formats
        """
        if not self.__check_session():
            return
        if (self.IS_OAT or self.IS_ELF) and self.lief.has_interpreter:
            self.log("info", "Interpreter : {0}".format(self.lief.interpreter))
        else:
            self.log("warning", "No interpreter found")

    def dynamic(self):
        """
            Display dynamic libraries of ELF, PE, Mach-O and OAT formats
        """
        if not self.__check_session():
            return
        rows = []
        if (self.IS_OAT or self.IS_ELF or self.IS_PE) and self.lief.libraries:
            self.log("info", "Dynamic libraries : ")
            for lib in self.lief.libraries:
                self.log("info", lib)
        elif self.IS_MACHO and self.lief.libraries:
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
            self.log("table", dict(header=["Command", "Name", "Offset", "Compatibility version", "Current version", "Size", "Timestamp"], rows=rows))
        else:
            self.log("warning", "No dynamic library found")

    def symbols(self):
        """
            Display symbols of ELF, Mach-O and OAT formats
        """
        if not self.__check_session():
            return
        rows = []
        if (self.IS_OAT or self.IS_ELF) and self.lief.symbols:
            self.printElfAndOatSymbols(self.lief.symbols, "Static and dynamic symbols")
        elif self.IS_MACHO and self.lief.symbols:
            self.log("info", "MachO symbols : ")
            for symbol in self.lief.symbols:
                rows.append([
                    symbol.name,
                    hex(symbol.description),
                    symbol.numberof_sections,
                    hex(symbol.type),
                    hex(symbol.value),
                    self.liefConstToString(symbol.origin)
                ])
            self.log("info", "Mach-O symbols : ")
            self.log("table", dict(header=["Name", "Description", "Nb of sections", "Type", "Value", "Origin"], rows=rows))
        else:
            self.log("warning", "No symbol found")

    def dlls(self):
        """
            Display PE binary imported dlls if any
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.libraries:
            self.log("info", "PE dlls : ")
            for lib in self.lief.libraries:
                self.log("info", lib)
        else:
            self.log("error", "No DLL found")

    def imports(self):
        """
            Display Pe imports if any
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.imports:
            self.log("info", "PE imports")
            for imp in self.lief.imports:
                self.log("info", "{0}".format(imp.name))
                for function in imp.entries:
                    self.log("item", "{0} : {1}".format(hex(function.iat_address), function.name))
        else:
            self.log("warning", "No import found")

    def imphash(self):
        """
            Display PE imphash
        """
        if not self.__check_session():
            return
        if self.IS_PE:
            self.log("info", "Imphash : {0}".format(lief.PE.get_imphash(self.lief)))
        else:
            self.log("warning", "No imphash found")

    def gnu_hash(self):
        """
            Display GNU hash of ELF and OAT formats
        """
        if not self.__check_session():
            return
        if (self.IS_OAT and self.lief.use_gnu_hash) or (self.IS_ELF and not self.IS_OAT and self.lief.gnu_hash):
            self.log("info", "GNU hash : ")
            self.log("item", "{0} : {1}".format("Number of buckets", self.lief.gnu_hash.nb_buckets))
            self.log("item", "{0} : {1}".format("First symbol index", hex(self.lief.gnu_hash.symbol_index)))
            self.log("item", "{0} : {1}".format("Bloom filters", ', '.join(str(hex(fil)) for fil in self.lief.gnu_hash.bloom_filters)))
            self.log("item", "{0} : {1}".format("Hash buckets", ', '.join(str(hex(bucket)) for bucket in self.lief.gnu_hash.buckets)))
            self.log("item", "{0} : {1}".format("Hash values", ', '.join(str(hex(h)) for h in self.lief.gnu_hash.hash_values)))
        else:
            self.log("warning", "No GNU hash found")

    def compileDate(self):
        """
            Display PE compilation date
        """
        if not self.__check_session():
            return
        if self.IS_PE:
            self.log("info", "Compilation date : {0}".format(self.fromTimestampToDate(self.lief.header.time_date_stamps)))
        else:
            self.log("warning", "No compilation date found")

    def strip(self):
        """
            Strip ELF and OAT formats
        """
        if not self.__check_session():
            return
        if self.IS_OAT or self.IS_ELF:
            self.lief.strip()
            self.log("success", "The binary has been stripped")
            self.log("warning", "Do not forget --write (-w) option if you want your stripped binary to be saved")
        else:
            self.log("warning", "Binary must be of type ELF or OAT")

    def write(self):
        """
            Write the open binary into another file, useful after being stripped
            A destination folder can be set (default ./)
        """
        if not self.__check_session():
            return
        fileName = self.args.write[0]
        destFolder = './' if '/' not in fileName else fileName[:fileName.rfind('/') + 1]
        if os.path.isfile(fileName):
            self.log("error", "File already exists")
        elif not os.access(destFolder, os.X_OK | os.W_OK):
            self.log("error", "Cannot write into folder : {0}".format(destFolder))
        elif fileName[len(fileName) - 1] == '/':
            self.log("error", "Please enter a file name")
        else:
            self.lief.write(fileName)
            self.log("success", "File successfully saved")

    def notes(self):
        """
            Display ELF and OAT notes
        """
        if not self.__check_session():
            return
        if (self.IS_OAT or self.IS_ELF) and self.lief.has_notes:
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

    def map(self):
        """
            Display DEX map items
        """
        if not self.__check_session():
            return
        rows = []
        if self.IS_DEX and self.lief.map:
            for item in self.lief.map.items:
                rows.append([
                    self.liefConstToString(item.type),
                    hex(item.offset),
                    "{0:<5} bytes".format(item.size)
                ])
            self.log("info", "DEX map items : ")
            self.log("table", dict(header=["Type", "Offset", "Size"], rows=rows))
        else:
            self.log("warning", "No map found")

    def header(self):
        """
            Display header of ELF, PE, Mach-O, OAT, DEX, VDEX and ART formats
        """
        if not self.__check_session():
            return
        if self.IS_ART:
            self.log("info", "ART header : ")
            self.log("item", "{0:<17} : {1}".format("Magic", self.formatMagicList(self.lief.header.magic)))
            self.log("item", "{0:<17} : {1}".format("Version", self.lief.header.version))
            self.log("item", "{0:<17} : {1}".format("Image begin", hex(self.lief.header.image_begin)))
            self.log("item", "{0:<17} : {1} bytes".format("Image size", self.lief.header.image_size))
            self.log("item", "{0:<17} : {1}".format("Checksum", hex(self.lief.header.oat_checksum)))
            self.log("item", "{0:<17} : {1}".format("OAT file begin", hex(self.lief.header.oat_file_begin)))
            self.log("item", "{0:<17} : {1}".format("OAT file end", hex(self.lief.header.oat_file_end)))
            self.log("item", "{0:<17} : {1}".format("Patch delta", self.lief.header.patch_delta))
            self.log("item", "{0:<17} : {1} bytes".format("Pointer size", self.lief.header.pointer_size))
            self.log("item", "{0:<17} : {1}".format("Compile pic", "Yes" if self.lief.header.compile_pic else "No"))
            self.log("item", "{0:<17} : {1}".format("Nb of sections", self.lief.header.nb_sections))
            self.log("item", "{0:<17} : {1}".format("Nb of methods", self.lief.header.nb_methods))
            self.log("item", "{0:<17} : {1}".format("Boot image begin", hex(self.lief.header.boot_image_begin)))
            self.log("item", "{0:<17} : {1} bytes".format("Boot image size", self.lief.header.boot_image_size))
            self.log("item", "{0:<17} : {1}".format("Boot OAT begin", hex(self.lief.header.boot_oat_begin)))
            self.log("item", "{0:<17} : {1} bytes".format("Boot OAT size", self.lief.header.boot_oat_size))
            self.log("item", "{0:<17} : {1}".format("Storage mode", self.liefConstToString(self.lief.header.storage_mode)))
            self.log("item", "{0:<17} : {1} bytes".format("Data size", self.lief.header.data_size))
        elif self.IS_VDEX:
            self.log("info", "VDEX header : ")
            self.log("item", "{0:<22} : {1}".format("Magic", self.formatMagicList(self.lief.header.magic)))
            self.log("item", "{0:<22} : {1}".format("Nb of DEX files", self.lief.header.nb_dex_files))
            self.log("item", "{0:<22} : {1} bytes".format("Size of info section", self.lief.header.quickening_info_size))
            self.log("item", "{0:<22} : {1} bytes".format("Size of deps section", self.lief.header.verifier_deps_size))
            self.log("item", "{0:<22} : {1} bytes".format("Size of all DEX files", self.lief.header.dex_size))
            self.log("item", "{0:<22} : {1}".format("Version", self.lief.header.version))
        elif self.IS_DEX:
            self.log("info", "DEX header : ")
            self.log("item", "{0:<17} : {1}".format("Magic", self.formatMagicList(self.lief.header.magic)))
            self.log("item", "{0:<17} : {1}".format("Checksum", hex(self.lief.header.checksum)))
            self.log("item", "{0:<17} : {1}".format("Endianness", hex(self.lief.header.endian_tag)))
            self.log("item", "{0:<17} : {1}".format("Location", self.lief.location if self.lief.location else '-'))
            self.log("item", "{0:<17} : {1} bytes".format("Size", self.lief.header.file_size))
            self.log("item", "{0:<17} : {1} bytes".format("Header size", self.lief.header.header_size))
            self.log("item", "{0:<17} : {1}".format("Map offset", hex(self.lief.header.map_offset)))
            self.log("item", "{0:<17} : {1}".format("Signature", ''.join(str(hex(sig))[2:] for sig in self.lief.header.signature)))
            self.log("item", "{0:<17} : {1}".format("DEX version", self.lief.version))
            self.log("item", "{0:<17} : {1}".format("Nb of Prototypes", "{0:<6} => id : {1}".format(self.lief.header.prototypes[1], hex(self.lief.header.prototypes[0]))))
            self.log("item", "{0:<17} : {1}".format("Nb of Strings", "{0:<6} => id : {1}".format(self.lief.header.strings[1], hex(self.lief.header.strings[0]))))
            self.log("item", "{0:<17} : {1}".format("Nb of Classes", "{0:<6} => id : {1}".format(self.lief.header.classes[1], hex(self.lief.header.classes[0]))))
            self.log("item", "{0:<17} : {1}".format("Nb of Fields", "{0:<6} => id : {1}".format(self.lief.header.fields[1], hex(self.lief.header.fields[0]))))
            self.log("item", "{0:<17} : {1}".format("Nb of Methods", "{0:<6} => id : {1}".format(self.lief.header.methods[1], hex(self.lief.header.methods[0]))))
            self.log("item", "{0:<17} : {1}".format("Nb of Types", "{0:<6} => id : {1}".format(self.lief.header.types[1], hex(self.lief.header.types[0]))))
            self.log("item", "{0:<17} : {1}".format("Nb of Data", "{0:<6} => id : {1}".format(self.lief.header.data[1], hex(self.lief.header.data[0]))))
            self.log("item", "{0:<17} : {1}".format("Nb of Link", "{0:<6} => id : {1}".format(self.lief.header.link[1], hex(self.lief.header.link[0]))))
        elif self.IS_OAT:
            self.log("info", "OAT header : ")
            self.log("item", "{0:<37} : {1}".format("Magic", self.formatMagicList(self.lief.header.magic)))
            self.log("item", "{0:<37} : {1}".format("Checksum", hex(self.lief.header.checksum)))
            self.log("item", "{0:<37} : {1}".format("ImageBase", hex(self.lief.imagebase) if self.lief.imagebase else '-'))
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
            self.log("item", "{0:<37} : {1}".format("Number of dex files", self.lief.header.nb_dex_files))
            self.log("item", "{0:<37} : {1}".format("Oat dex files offset", hex(self.lief.header.oat_dex_files_offset)))
            self.log("item", "{0:<37} : {1}".format("Quick generic JNI trampoline offset", hex(self.lief.header.quick_generic_jni_trampoline_offset)))
            self.log("item", "{0:<37} : {1}".format("Quick IMT conflict trampoline offset", hex(self.lief.header.quick_imt_conflict_trampoline_offset)))
            self.log("item", "{0:<37} : {1}".format("Quick resolution trampoline offset", hex(self.lief.header.quick_resolution_trampoline_offset)))
            self.log("item", "{0:<37} : {1}".format("Quick to interpreter bridge offset", hex(self.lief.header.quick_to_interpreter_bridge_offset)))
            self.log("item", "{0:<37} : {1}".format("Version", self.lief.header.version))
        elif self.IS_MACHO:
            self.log("info", "MachO header : ")
            self.log("item", "{0:<15} : {1}".format("CPU type", self.liefConstToString(self.lief.header.cpu_type)))
            self.log("item", "{0:<15} : {1}".format("File type", self.liefConstToString(self.lief.header.file_type)))
            self.log("item", "{0:<15} : {1}".format("Number of cmds", self.lief.header.nb_cmds))
            self.log("item", "{0:<15} : {1} bytes".format("Size of cmds", self.lief.header.sizeof_cmds))
            self.log("item", "{0:<15} : {1}".format("Flags", ':'.join(self.liefConstToString(flag) for flag in self.lief.header.flags_list)))
        elif self.IS_PE:
            self.log("info", "PE header : ")
            self.log("item", "{0:<28} : {1}".format("Magic", self.formatMagicList(self.lief.header.signature)))
            self.log("item", "{0:<28} : {1}".format("Type", self.liefConstToString(self.lief.header.machine)))
            self.log("item", "{0:<28} : {1}".format("Number of sections", self.lief.header.numberof_sections))
            self.log("item", "{0:<28} : {1}".format("Number of symbols", self.lief.header.numberof_symbols))
            self.log("item", "{0:<28} : {1}".format("Pointer to symbol table", hex(self.lief.header.pointerto_symbol_table)))
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
        elif self.IS_ELF:
            self.log("info", "ELF header : ")
            self.log("item", "{0:<26} : {1}".format("Magic", self.formatMagicList(self.lief.header.identity)))
            self.log("item", "{0:<26} : {1}".format("Type", self.liefConstToString(self.lief.header.file_type)))
            self.log("item", "{0:<26} : {1}".format("Entrypoint", hex(self.lief.header.entrypoint)))
            self.log("item", "{0:<26} : {1}".format("ImageBase", hex(self.lief.imagebase) if self.lief.imagebase else '-'))
            self.log("item", "{0:<26} : {1} bytes".format("Header size", self.lief.header.header_size))
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
        """
            Display Mach-O code signature if any
        """
        if not self.__check_session():
            return
        if self.IS_MACHO and self.lief.has_code_signature:
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
        """
            Display ELf, PE, Mach-O and OAT exported functions if any
        """
        if not self.__check_session():
            return
        if ((self.IS_MACHO and self.lief.exported_functions)
                or (self.IS_OAT and self.lief.exported_functions)
                or (self.IS_ELF and self.lief.exported_functions)
                or (self.IS_PE and self.lief.exported_functions)):
            self.log("info", "Exported functions : ")
            for function in self.lief.exported_functions:
                self.log("info", function)
        else:
            self.log("warning", "No exported function found")

    def exportedSymbols(self):
        """
            Display ELF, Mach-O and OAT exported symbols if any
        """
        if not self.__check_session():
            return
        if (self.IS_OAT or self.IS_ELF) and self.lief.exported_symbols:
            self.printElfAndOatSymbols(self.lief.exported_symbols, "Exported symbols")
        elif self.IS_MACHO and self.lief.exported_symbols:
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
        """
            Display ELF, PE, Mach-O and OAT imported functions if any
        """
        if not self.__check_session():
            return
        if ((self.IS_MACHO and self.lief.imported_functions)
                or (self.IS_OAT and self.lief.imported_functions)
                or (self.IS_ELF and self.lief.imported_functions)
                or (self.IS_PE and self.lief.imported_functions)):
            self.log("info", "Imported functions : ")
            for function in self.lief.imported_functions:
                self.log("info", function)
        else:
            self.log("warning", "No imported function found")

    def importedSymbols(self):
        """
            Display ELF, Mach-O and OAT imported symbols if any
        """
        if not self.__check_session():
            return
        rows = []
        if (self.IS_OAT or self.IS_ELF) and self.lief.imported_symbols:
            self.printElfAndOatSymbols(self.lief.imported_symbols, "Imported symbols")
        elif self.IS_MACHO and self.lief.imported_symbols:
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
        """
            Display Mach-O source version if any
        """
        if not self.__check_session():
            return
        if self.IS_MACHO and self.lief.has_source_version:
            self.log("info", "Source version : ")
            self.log("item", "{0:<10} : {1}".format("command", self.liefConstToString(self.lief.source_version.command)))
            self.log("item", "{0:<10} : {1}".format("Offset", hex(self.lief.source_version.command_offset)))
            self.log("item", "{0:<10} : {1} bytes".format("size", self.lief.source_version.size))
            self.log("item", "{0:<10} : {1}".format("Version", self.listVersionToDottedVersion(self.lief.source_version.version)))
        else:
            self.log("warning", "No source version found")

    def subFramework(self):
        """
            Display Mach-O sub-framework if any
        """
        if not self.__check_session():
            return
        if self.IS_MACHO and self.lief.has_sub_framework:
            self.log("info", "Sub-framework : ")
            self.log("item", "{0:<10} : {1}".format("Command", self.liefConstToString(self.lief.sub_framework.command)))
            self.log("item", "{0:<10} : {1}".format("Offset", hex(self.lief.sub_framework.command_offset)))
            self.log("item", "{0:<10} : {1} bytes".format("Size", self.lief.sub_framework.size))
            self.log("item", "{0:<10} : {1}".format("Umbrella", self.lief.sub_framework.umbrella))
        else:
            self.log("warning", "No sub-framework found")

    def uuid(self):
        """
            Display Mach-O uuid if any
        """
        if not self.__check_session():
            return
        if self.IS_MACHO and self.lief.has_uuid:
            self.log("info", "Uuid : ")
            self.log("item", "{0:<10} : {1}".format("Command", self.liefConstToString(self.lief.uuid.command)))
            self.log("item", "{0:<10} : {1}".format("Offset", hex(self.lief.uuid.command_offset)))
            self.log("item", "{0:<10} : {1} bytes".format("Size", self.lief.uuid.size))
            self.log("item", "{0:<10} : {1}".format("Uuid", self.listUuidToUuid(self.lief.uuid.uuid)))
        else:
            self.log("warning", "No uuid found")

    def dataInCode(self):
        """
            Display Mach-O data in code if any
        """
        if not self.__check_session():
            return
        if self.IS_MACHO and self.lief.has_data_in_code:
            self.log("info", "Data in code : ")
            self.log("item", "{0:<12} : {1}".format("Command", self.liefConstToString(self.lief.data_in_code.command)))
            self.log("item", "{0:<12} : {1}".format("Offset", hex(self.lief.data_in_code.command_offset)))
            self.log("item", "{0:<12} : {1} bytes".format("Size", self.lief.data_in_code.size))
            self.log("item", "{0:<12} : {1}".format("Data Offset", hex(self.lief.data_in_code.data_offset)))
        else:
            self.log("warning", "No data in code found")

    def mainCommand(self):
        """
            Display Mach-O main command if any
        """
        if not self.__check_session():
            return
        if self.IS_MACHO and self.lief.has_main_command:
            self.log("info", "Main command : ")
            self.log("item", "{0:<12} : {1}".format("Command", self.liefConstToString(self.lief.main_command.command)))
            self.log("item", "{0:<12} : {1}".format("Offset", hex(self.lief.main_command.command_offset)))
            self.log("item", "{0:<12} : {1} bytes".format("Size", self.lief.main_command.size))
            self.log("item", "{0:<12} : {1}".format("Entrypoint", hex(self.lief.main_command.entrypoint)))
            self.log("item", "{0:<12} : {1} bytes".format("Stack size", self.lief.main_command.stack_size))
        else:
            self.log("warning", "No main command found")

    def commands(self):
        """
            Display all Mach-O commands
        """
        if not self.__check_session():
            return
        rows = []
        if self.IS_MACHO and self.lief.commands:
            for command in self.lief.commands:
                rows.append([
                    self.liefConstToString(command.command),
                    "{0:<6} bytes".format(command.size),
                    hex(command.command_offset),
                ])
            self.log("info", "MachO commands : ")
            self.log("table", dict(header=["Command", "Size", "Offset"], rows=rows))
        else:
            self.log("warning", "No command found")

    def dosHeader(self):
        """
            Display PE DOS header
        """
        if not self.__check_session():
            return
        if self.IS_PE:
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
        """
            Display PE data directories if any
        """
        if not self.__check_session():
            return
        rows = []
        if self.IS_PE and self.lief.data_directories:
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
        """
            Disaply PE DOS stub
        """
        if not self.__check_session():
            return
        if self.IS_PE:
            rawDosStub = ''.join(chr(stub) if chr(stub) in string.printable.replace(string.whitespace, '') else '.' for stub in self.lief.dos_stub)
            printableDosStub = [rawDosStub[i:i + 16] for i in range(0, len(rawDosStub), 16)]
            self.log("info", "{0}{1}".format('DOS stub : \n', '\n'.join(printableDosStub)))
        else:
            self.log("warning", "No DOS stub found")

    def debug(self):
        """
            Display PE debug information
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_debug:
            self.log("info", "Debug information : ")
            debug = self.lief.debug
            self.log("item", "{0:<28} : {1}".format("Address of Raw data", hex(debug.addressof_rawdata)))
            self.log("item", "{0:<28} : {1}".format("Minor version of debug data", debug.minor_version))
            self.log("item", "{0:<28} : {1}".format("Major version of debug data", debug.major_version))
            self.log("item", "{0:<28} : {1}".format("Pointer to raw data", hex(debug.pointerto_rawdata)))
            self.log("item", "{0:<28} : {1} bytes".format("Size of data", debug.sizeof_data))
            self.log("item", "{0:<28} : {1}".format("Data of data creation", self.fromTimestampToDate(debug.timestamp)))
            self.log("item", "{0:<28} : {1}".format("Type of debug information", self.liefConstToString(debug.type)))
            if debug.has_code_view:
                self.log("item", "{0:<28} : {1}".format("Code view", self.liefConstToString(debug.code_view.cv_signature)))
                if isinstance(debug.code_view, lief.PE.CodeViewPDB):
                    self.log("item", "{0:<28} : {1}".format("Age", debug.code_view.age))
                    self.log("item", "{0:<28} : {1}".format("Signature", ''.join(str(hex(sig))[2:] for sig in debug.code_view.signature)))
                    self.log("item", "{0:<28} : {1}".format("Path", debug.code_view.filename))
        else:
            self.log("warning", "No debug information found")

    def loadConfiguration(self):
        """
            Display PE load configuration if any
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_configuration:
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

    def dynamicRelocations(self):
        """
            Display OAT dynamic relocations if any
        """
        if not self.__check_session():
            return
        rows = []
        if self.IS_OAT and self.lief.dynamic_relocations:
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

    def objectRelocations(self):
        """
            Display ELF and OAT object relocations if any
        """
        if not self.__check_session():
            return
        if (self.IS_OAT or self.IS_ELF) and self.lief.object_relocations:
            self.printElfAndOatRelocations(self.lief.object_relocations, "Object relocations")
        else:
            self.log("warning", "No object relocation found")

    def relocations(self):
        """
            Display ELF, PE and OAT relocations if any
        """
        if not self.__check_session():
            return
        rows = []
        if (self.IS_OAT or self.IS_ELF) and self.lief.relocations:
            self.printElfAndOatRelocations(self.lief.relocations, "Relocations")
        elif self.IS_PE and self.lief.has_relocations:
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
        """
            Display PE resources if any
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_resources:
            self.log("info", "PE resources : ")
            self.log("item", "{0:<17} : {1}".format("Name", self.lief.resources.name if self.lief.resources.has_name else "No name"))
            self.log("item", "{0:<17} : {1}".format("Number of childs", len(self.lief.resources.childs)))
            self.log("item", "{0:<17} : {1}".format("Depth", self.lief.resources.depth))
            self.log("item", "{0:<17} : {1}".format("Type", "Directory" if self.lief.resources.is_directory else "Data" if self.lief.resources.is_data else "Unknown"))
            self.log("item", "{0:<17} : {1}".format("Id", hex(self.lief.resources.id)))
        else:
            self.log("warning", "No resource found")

    def tls(self):
        """
            Display PE TLS if any
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_tls:
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
        """
            Display PE rich header if any
        """
        if not self.__check_session():
            return
        rows = []
        if self.IS_PE and self.lief.has_rich_header:
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
        """
            Display PE signature if any
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_signature:
            self.log("info", "PE signature : ")
            self.log("item", "{0:<20} : {1}".format("Version", self.lief.signature.version))
            self.log("item", "{0:<20} : {1}".format("Digestion algorithm", lief.PE.oid_to_string(self.lief.signature.digest_algorithm)))
            self.log("success", "Content information")
            self.log("item", "{0:<20} : {1}".format("Content type", lief.PE.oid_to_string(self.lief.signature.content_info.content_type)))
            self.log("item", "{0:<20} : {1}".format("Digest", self.lief.signature.content_info.digest if self.lief.signature.content_info.digest else '-'))
            self.log("item", "{0:<20} : {1}".format("Digest algorithm", self.lief.signature.content_info.digest_algorithm if self.lief.signature.content_info.digest_algorithm else '-'))
            self.log("success", "Certificates")
            for index, certificate in enumerate(self.lief.signature.certificates):
                self.log("info", "Certificate N°{0}".format(index + 1))
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
        """
            Display PE manifest if any
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_resources and self.lief.resources_manager.has_manifest:
            self.log("info", "PE manifest : \n{0}".format(self.lief.resources_manager.manifest))
        else:
            self.log("warning", "No manifest found")

    def resourcesTypes(self):
        """
            Display PE resources types if any
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_resources and self.lief.resources_manager.has_type:
            self.log("info", "Resources types availables : {0}".format(", ".join(self.liefConstToString(rType) for rType in self.lief.resources_manager.types_available)))
        else:
            self.log("warning", "No resources type found")

    def langs(self):
        """
            Display PE used lands and sublangs
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_resources and self.lief.resources_manager.langs_available:
            self.log("info", "Langs availables      : {0}".format(", ".join(self.liefConstToString(lang) for lang in self.lief.resources_manager.langs_available)))
            self.log("info", "Sublangs availables   : {0}".format(", ".join(self.liefConstToString(sublang) for sublang in self.lief.resources_manager.sublangs_available)))
        else:
            self.log("warning", "No lang found")

    def icons(self):
        """
            Display PE embedded icons if any
        """
        if not self.__check_session():
            return
        rows = []
        if self.IS_PE and self.lief.has_resources and self.lief.resources_manager.has_icons:
            for icon in self.lief.resources_manager.icons:
                rows.append([icon.id,
                             "{0} x {1}".format(icon.width, icon.height),
                             icon.bit_count,
                             icon.color_count,
                             self.liefConstToString(icon.lang),
                             self.liefConstToString(icon.sublang)])
            self.log("info", "PE icons : ")
            self.log("table", dict(header=["ID", "Size", "Bits/pixel", "Nb colors/icon", "Lang", "Sublang"], rows=rows))
        else:
            self.log("warning", "No icon found")

    def extractIcons(self):
        """
            Extract PE embedded icons if any
            A destination folder can be set (default ./)
            An icon id can be set (default all)
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_resources and self.lief.resources_manager.has_icons:
            iconExists = False

            def iconProcessing(icon, destFolder):
                fileName = "{0}{1}_{2}.ico".format(destFolder, self.lief.name.replace('.', '_'), icon.id)
                if os.path.isfile(fileName):
                    self.log("error", "{0:<25} : {1}".format("File already exists", fileName))
                else:
                    icon.save(fileName)
                    self.log("success", "{0:<25} : {1}".format("File successfully saved", fileName))
            destFolder = self.args.extracticons
            if destFolder[len(destFolder) - 1] != '/':
                destFolder += '/'
            if not os.access(destFolder, os.X_OK | os.W_OK):
                self.log("error", "Cannot write into folder : {0}".format(destFolder))
            else:
                for icon in self.lief.resources_manager.icons:
                    if self.args.id:
                        if self.args.id[0] == icon.id:
                            iconExists = True
                            iconProcessing(icon, destFolder)
                    else:
                        iconProcessing(icon, destFolder)
                if self.args.id and not iconExists:
                    self.log("warning", "Icon does not exist")
        else:
            self.log("warning", "No icon found")

    def dialogs(self):
        """
            Display PE dialogs if any
        """
        if not self.__check_session():
            return
        if self.IS_PE and self.lief.has_resources and self.lief.resources_manager.has_dialogs:
            for index, dialog in enumerate(self.lief.resources_manager.dialogs):
                self.log("info", "Dialog N°{0}".format(index + 1))
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
                    self.log("success", "Item in dialog N°{0} of id {1}".format(index + 1, item.id))
                    self.log("item", "{0:<31} : {1}".format("Title", item.title))
                    self.log("item", "{0:<31} : {1:<5} px".format("Width of item", item.cx))
                    self.log("item", "{0:<31} : {1:<5} px".format("Height of item", item.cy))
                    self.log("item", "{0:<31} : {1}".format("Help id", item.help_id))
                    self.log("item", "{0:<31} : {1}".format("Upper-left corner x coordinate", item.x))
                    self.log("item", "{0:<31} : {1}".format("Upper-left corner y coordinate", item.y))
        else:
            self.log("warning", "No dialog found")

    def classes(self):
        """
            Display OAT and DEX classes
        """
        if not self.__check_session():
            return
        rows = []
        if self.IS_OAT and self.lief.classes:
            for cl in self.lief.classes:
                rows.append([
                    self.prettyJavaClassFullName(cl.fullname),
                    cl.index,
                    len(cl.methods),
                    self.liefConstToString(cl.status),
                    self.liefConstToString(cl.type),
                ])
            self.log("info", "OAT classes : ")
            self.log("table", dict(header=["Name", "index", "Methods", "Status", "Type"], rows=rows))
        elif self.IS_DEX and self.lief.classes:
            for cl in self.lief.classes:
                rows.append([
                    cl.pretty_name,
                    ' '.join(self.liefConstToString(flag) for flag in cl.access_flags) if cl.access_flags else '-',
                    hex(cl.index) if cl.index else '-',
                    len(cl.methods),
                    cl.parent.name if cl.has_parent else '-',
                    cl.source_filename if cl.source_filename else '-'
                ])
            self.log("info", "DEX classes : ")
            self.log("table", dict(header=["Name", "Flags", "index", "Methods", "Parent class", "Source filename"], rows=rows))
        else:
            self.log("warning", "No class found")

    def methods(self):
        """
            Display OAT and DEX methods by class
            A class name must be set
            A method name can be set (default all)
        """
        if not self.__check_session():
            return

        def oatMethodProcessing(method):
            self.log("info", "Information of method {0} : ".format(method.name))
            self.log("item", "{0:<17} : {1}".format("Name", method.name))
            self.log("item", "{0:<17} : {1}".format("Compiled", "Yes" if method.is_compiled else "No"))
            self.log("item", "{0:<17} : {1}".format("Dex optimization", "Yes" if method.is_dex2dex_optimized else "No"))
            self.log("item", "{0:<17} : {1}".format("Dex method", "Yes" if method.has_dex_method else "No"))
            methodProcessing(method.dex_method)

        def dexMethodProcessing(method):
            self.log("info", "Information of method {0} : ".format(method.name))
            self.log("item", "{0:<17} : {1}".format("Name", method.name))
            methodProcessing(method)

        def methodProcessing(method):
            self.log("item", "{0:<17} : {1}".format("Access flags", ' '.join(self.liefConstToString(flag) for flag in method.access_flags) if method else '-'))
            self.log("item", "{0:<17} : {1}".format("Offset", hex(method.code_offset) if method else '-'))
            self.log("item", "{0:<17} : {1}".format("Virtual method", '-' if not method else "Yes" if method.is_virtual else "No"))
            self.log("item", "{0:<17} : {1}".format("Parameters type", '-' if not method else ", ".join(self.liefConstToString(paramType.value) if paramType.type == lief.DEX.Type.TYPES.PRIMITIVE else paramType.value.pretty_name if paramType.type == lief.DEX.Type.TYPES.CLASS else '-' for paramType in method.prototype.parameters_type) if method.prototype.parameters_type else '-'))
            self.log("item", "{0:<17} : {1}".format("Return type", '-' if not method else self.liefConstToString(method.prototype.return_type.value) if method.prototype.return_type.type == lief.DEX.Type.TYPES.PRIMITIVE else method.prototype.return_type.value.pretty_name if method.prototype.return_type.type == lief.DEX.Type.TYPES.CLASS else '-'))
        if (self.IS_OAT or self.IS_DEX) and self.lief.methods:
            if self.args.classname:
                className = self.args.classname[0]
                classExists = False
                methodExists = False
                if self.lief.classes:
                    for cl in self.lief.classes:
                        if self.prettyJavaClassFullName(cl.fullname) == className:
                            classExists = True
                            if cl.methods:
                                for method in cl.methods:
                                    if self.args.name:
                                        if self.args.name[0] == method.name:
                                            methodExists = True
                                            if self.IS_OAT:
                                                oatMethodProcessing(method)
                                            elif self.IS_DEX:
                                                dexMethodProcessing(method)
                                    else:
                                        if self.IS_OAT:
                                            oatMethodProcessing(method)
                                        elif self.IS_DEX:
                                            dexMethodProcessing(method)
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

    def androidVersion(self):
        """
            Display OAT, VDEX and ART android version
        """
        if not self.__check_session():
            return
        try:
            androidversion = None
            if self.IS_OAT:
                androidversion = "{0} ({1})".format(lief.Android.version_string(lief.OAT.android_version(lief.OAT.version(self.lief))), lief.Android.code_name(lief.OAT.android_version(lief.OAT.version(self.lief))))
            elif self.IS_VDEX:
                androidversion = "{0} ({1})".format(lief.Android.version_string(lief.VDEX.android_version(lief.VDEX.version(self.FILE_PATH))), lief.Android.code_name(lief.VDEX.android_version(lief.VDEX.version(self.FILE_PATH))))
            elif self.IS_ART:
                androidversion = "{0} ({1})".format(lief.Android.version_string(lief.ART.android_version(lief.ART.version(self.FILE_PATH))), lief.Android.code_name(lief.ART.android_version(lief.ART.version(self.FILE_PATH))))
            if androidversion:
                self.log("info", "Android version : {0}".format(androidversion))
            else:
                self.log("warning", "No android version found")
        except Exception as e:
            self.log("error", "Problem with android version : {0}".format(e))

    def dexFiles(self):
        """
            Display OAT and VDEX dex files
        """
        if not self.__check_session():
            return
        rows = []
        if (self.IS_OAT or self.IS_VDEX) and self.lief.dex_files:
            for dexFile in self.lief.dex_files:
                rows.append([
                    dexFile.name,
                    hex(dexFile.header.endian_tag),
                    "{0} bytes".format(dexFile.header.file_size),
                    dexFile.location if dexFile.location else '-',
                ])
            self.log("info", "Dex files : ")
            self.log("table", dict(header=["Name", "Endianness", "Size", "Location"], rows=rows))
        else:
            self.log("warning", "No dex file found")

    def dynamicEntries(self):
        """
            Display ELF and OAT dynamic entries
        """
        if not self.__check_session():
            return
        rows = []
        if (self.IS_OAT or self.IS_ELF) and self.lief.dynamic_entries:
            for dynamicEntry in self.lief.dynamic_entries:
                rows.append([
                    self.liefConstToString(dynamicEntry.tag),
                    hex(dynamicEntry.value)
                ])
            self.log("info", "Dynamic entries: ")
            self.log("table", dict(header=["Tag", "Value"], rows=rows))
        else:
            self.log("warning", "No dynamic entry found")

    def dynamicSymbols(self):
        """
            Display ELF and OAT dynamic symbols
        """
        if not self.__check_session():
            return
        if (self.IS_OAT or self.IS_ELF) and self.lief.dynamic_symbols:
            self.printElfAndOatSymbols(self.lief.dynamic_symbols, "Dynamic symbols")
        else:
            self.log("warning", "No dynamic symbol found")

    def staticSymbols(self):
        """
            Display ELF and OAT static symbols
        """
        if not self.__check_session():
            return
        if (self.IS_OAT or self.IS_ELF) and self.lief.static_symbols:
            self.printElfAndOatSymbols(self.lief.static_symbols, "Static symbols")
        else:
            self.log("warning", "No static symbol found")

    def extractDexFiles(self):
        """
            Extract dex files from OAT and VDEX formats
            A destination folder can be set (default ./)
            A dex file name can be set (default all)
        """
        if not self.__check_session():
            return
        if (self.IS_OAT or self.IS_VDEX) and self.lief.dex_files:
            dexFileExists = False

            def dexFileProcessing(dexFile, destFolder):
                fileName = "{0}{1}_{2}".format(destFolder, hex(dexFile.header.checksum), dexFile.name)
                if os.path.isfile(fileName):
                    self.log("error", "{0:<25} : {1}".format("File already exists", fileName))
                else:
                    dexFile.save(fileName)
                    self.log("success", "{0:<25} : {1}".format("File successfully saved", fileName))
            destFolder = self.args.extractdexfiles
            if destFolder[len(destFolder) - 1] != '/':
                destFolder += '/'
            if not os.access(destFolder, os.X_OK | os.W_OK):
                self.log("error", "Cannot write into folder : {0}".format(destFolder))
            else:
                for dexFile in self.lief.dex_files:
                    if self.args.name:
                        if self.args.name[0] == dexFile.name:
                            dexFileExists = True
                            dexFileProcessing(dexFile, destFolder)
                    else:
                        dexFileProcessing(dexFile, destFolder)
                if self.args.name and not dexFileExists:
                    self.log("warning", "Dex file does not exist")
        else:
            self.log("warning", "No dexFile found")

    def strings(self):
        """
            Display DEX strings
        """
        if not self.__check_session():
            return
        if self.IS_DEX and self.lief.strings:
            self.log("info", "DEX strings : ")
            for dex_string in self.lief.strings:
                if dex_string:
                    self.log("item", "{0}".format(dex_string))
        else:
            self.log("warning", "No string found")

    """Usefuls methods"""

    def formatMagicList(self, magicList):
        """
            Formatting of magic list of bytes

            :param (list) magicList : List of bytes representing the magic identifier of the binary
            :return (str) : Pretty representation of magic identifier
        """
        if not magicList:
            return None
        return "{0} ({1})".format(''.join(chr(m) if chr(m) in string.printable.replace(string.whitespace, '') else "'\\{0}'".format(m) for m in magicList), ' '.join(str(hex(m))[2:] for m in magicList))

    def liefConstToString(self, const):
        """
            Conversion of lief const to printable const

            :param (lief constant) const : lief constant thus represented : CLASS.CONST
            :return (str) : Only the CONST part of the const parameter
        """
        return str(const).split('.')[1]

    def prettyJavaClassFullName(self, className):
        """
            Conversion of Java class name into nicer class name

            :param (str) className : Java class name thus represented : Lcom/android/..../;
            :return (str) : Pretty format of class name : com.android.etc...
        """
        if not className:
            return None
        return className[1:-1].replace('/', '.')

    def fromTimestampToDate(self, timestamp):
        """
            Conversion of timestamp into printable date

            :param (int) timestamp : Timestamp to be converted
            :return (str) : Formatted date : Jan 01 2019 at 00:00:00
        """
        if not timestamp:
            return None
        return datetime.utcfromtimestamp(timestamp).strftime("%b %d %Y at %H:%M:%S")

    def fromListOfDatetoDate(self, dateList):
        """
            Conversion of a date represented as a list into a printable date

            :param (list) dateList : date represented as a list : [Y, m, d, H, M, S] (example : [2019, 01, 01, 00, 00, 00])
            :return (str) : Formatted date : Jan 01 2019 at 00:00:00
        """
        if not dateList:
            return None
        dateString = '-'.join(str(value) for value in dateList)
        timestamp = datetime.strptime(dateString, "%Y-%m-%d-%H-%M-%S").timestamp()
        return self.fromTimestampToDate(timestamp)

    def getEntropy(self, data):
        """
            Entropy calculation of raw data

            :param (bytes) data : Raw data
            :return (float) : Entropy of raw data
        """
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
        """
            Conversion of a uuid represented as a list into formatted uuid

            :param (list) listUuid : List of bytes representing a uuid
            :return (str) : Formatted uuid thus represented : 00000000-0000-0000-0000-000000000000
        """
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
        """
            Conversion of a version represented as a list into dotted representation

            :param (list) listVersion : List of version values
            :return (str) : Formatted version : 0.0.0.0....
        """
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

    def printElfAndOatSymbols(self, symbols, title):
        """
            Code factorisation for elf and oat symbols display

            :param (list) symbols : List of symbols
            :param (str) title : Title for the display
        """
        rows = []
        if symbols:
            for symbol in symbols:
                rows.append([
                    symbol.name,
                    self.liefConstToString(symbol.type),
                    hex(symbol.value),
                    hex(symbol.size),
                    self.liefConstToString(symbol.visibility),
                    "Yes" if symbol.is_function else "No",
                    "Yes" if symbol.is_static else "No",
                    "Yes" if symbol.is_variable else "No"
                ])
            self.log("info", "{0} : ".format(title))
            self.log("table", dict(header=["Name", "Type", "Val", "Size", "Visibility", "isFun", "isStatic", "isVar"], rows=rows))
        else:
            self.log("warning", "No symbol found")

    def printElfAndOatRelocations(self, relocations, title):
        """
            Code factorisation for elf and oat relocations display

            :param (list) relocations : List of relocations
            :param (str) title : Title for the display
        """
        rows = []
        if relocations:
            for relocation in relocations:
                rows.append([
                    hex(relocation.address),
                    self.liefConstToString(relocation.purpose),
                    relocation.section.name if relocation.has_section else '-',
                    relocation.symbol.name if relocation.has_symbol else '-',
                ])
            self.log("info", "{0} : ".format(title))
            self.log("table", dict(header=["Address", "Purpose", "Section", "Symbol"], rows=rows))
        else:
            self.log("warning", "No relocation found")

    def parseBinary(self, binary):
        """
            Binary parsing for the self.lief variable

            :param (str) binary : The path of the binary file
            :return (lief.ELF.Binary or lief.PE.Binary or lief.MachO.Binary or lief.OAT.Binary or lief.DEX.File or lief.VDEX.File or lief.ART.File) : The lief binary
        """
        self.IS_PE = lief.is_pe(binary)
        self.IS_ELF = lief.is_elf(binary) and not lief.is_oat(binary)
        self.IS_MACHO = lief.is_macho(binary)
        self.IS_OAT = lief.is_oat(binary)
        self.IS_DEX = lief.is_dex(binary)
        self.IS_VDEX = lief.is_vdex(binary)
        self.IS_ART = lief.is_art(binary)
        try:
            if self.IS_OAT or self.IS_ELF or self.IS_MACHO or self.IS_PE:
                return lief.parse(binary)
            elif self.IS_DEX:
                return lief.DEX.parse(binary)
            elif self.IS_VDEX:
                return lief.VDEX.parse(binary)
            elif self.IS_ART:
                return lief.ART.parse(binary)
        except Exception as e:
            raise e

    def wrongBinaryType(self, expected):
        """
            Display error message if wring binary type for a command

            :param (str) expected : The binary type expected
        """
        self.log("error", "Wrong binary type")
        fileType = "MACH-O" if self.IS_MACHO else "OAT" if self.IS_OAT else "PE" if self.IS_PE else "ELF" if self.IS_ELF else "DEX" if self.IS_DEX else "VDEX" if self.IS_VDEX else "ART" if self.IS_ART else "UNKNOWN"
        self.log("info", "Expected filtype : {0}".format(expected))
        self.log("info", "Current filetype : {0}".format(fileType))

    """Binary type methods"""

    def pe(self):
        if not self.__check_session():
            return
        if not self.IS_PE:
            self.wrongBinaryType("PE")
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
        if not self.IS_ELF or self.IS_OAT:
            self.wrongBinaryType("ELF")
        else:
            if self.args.segments:
                self.segments()
            elif self.args.sections:
                self.sections()
            elif self.args.relocations:
                self.relocations()
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
            elif self.args.impsymbols:
                self.importedSymbols()
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
            elif self.args.dynamicsymbols:
                self.dynamicSymbols()
            elif self.args.dynamicentries:
                self.dynamicEntries()
            elif self.args.expsymbols:
                self.exportedSymbols()
            elif self.args.objectrelocations:
                self.objectRelocations()
            elif self.args.staticsymbols:
                self.staticSymbols()

    def oat(self):
        if not self.__check_session():
            return
        if not self.IS_OAT:
            self.wrongBinaryType("OAT")
        else:
            if self.args.segments:
                self.segments()
            elif self.args.sections:
                self.sections()
            elif self.args.extractdexfiles:
                self.extractDexFiles()
            elif self.args.staticsymbols:
                self.staticSymbols()
            elif self.args.dexfiles:
                self.dexFiles()
            elif self.args.relocations:
                self.relocations()
            elif self.args.androidversion:
                self.androidVersion()
            elif self.args.impfunctions:
                self.importedFunctions()
            elif self.args.write:
                self.write()
            elif self.args.classes:
                self.classes()
            elif self.args.dynamicentries:
                self.dynamicEntries()
            elif self.args.dynamicsymbols:
                self.dynamicSymbols()
            elif self.args.methods:
                self.methods()
            elif self.args.type:
                self.type()
            elif self.args.impsymbols:
                self.importedSymbols()
            elif self.args.objectrelocations:
                self.objectRelocations()
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
            elif self.args.expsymbols:
                self.exportedSymbols()

    def macho(self):
        if not self.__check_session():
            return
        if not self.IS_MACHO:
            self.wrongBinaryType("MACH-O")
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

    def dex(self):
        if not self.__check_session():
            return
        if not self.IS_DEX:
            self.wrongBinaryType("DEX")
        else:
            if self.args.classes:
                self.classes()
            if self.args.header:
                self.header()
            if self.args.map:
                self.map()
            if self.args.methods:
                self.methods()
            if self.args.strings:
                self.strings()

    def vdex(self):
        if not self.__check_session():
            return
        if not self.IS_VDEX:
            self.wrongBinaryType("VDEX")
        else:
            if self.args.header:
                self.header()
            elif self.args.androidversion:
                self.androidVersion()
            elif self.args.dexfiles:
                self.dexFiles()
            elif self.args.extractdexfiles:
                self.extractDexFiles()

    def art(self):
        if not self.__check_session():
            return
        if not self.IS_ART:
            self.wrongBinaryType("ART")
        else:
            if self.args.header:
                self.header()
            elif self.args.androidversion:
                self.androidVersion()

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
        elif self.args.subname == "dex":
            self.dex()
        elif self.args.subname == "vdex":
            self.vdex()
        elif self.args.subname == "art":
            self.art()
        else:
            self.log("error", "At least one of the parameters is required")
            self.usage()
