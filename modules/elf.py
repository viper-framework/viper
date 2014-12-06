# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.descriptions import describe_sh_flags 
    from elftools.elf.descriptions import describe_p_flags
    from elftools.elf.descriptions import describe_symbol_type
    from elftools.elf.dynamic import DynamicSection, DynamicSegment
    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

# Have a look at scripts/readelf.py - pyelftools
class ELF(Module):
    cmd = 'elf'
    description = 'Extract information from ELF headers'
    authors = ['emdel']

    def __init__(self):
        self.elf = None

    def __check_session(self):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return False

        if not self.elf:
            try:
                fd = open(__sessions__.current.file.path, 'rb')
                self.elf = ELFFile(fd)
            except:
                self.log('error', "Unable to parse ELF file")
                return False

        return True

    def segments(self):
        if not self.__check_session():
            return
        
        rows = []
        for segment in self.elf.iter_segments():
            rows.append([
                segment['p_type'],
                segment['p_vaddr'],
                hex(segment['p_filesz']),
                hex(segment['p_memsz']),
                describe_p_flags(segment['p_flags'])
            ])
                         
        self.log('info', "ELF Segments:") 
        self.log('table', dict(header=['Type', 'VirtAddr', 'FileSize', 'MemSize', 'Flags'], rows=rows))

    def sections(self):
        if not self.__check_session():
            return

        rows = []
        # TODO: Add get_entropy in pyelftools sections 
        for section in self.elf.iter_sections():
            rows.append([
                section.name,
                hex(section['sh_addr']), 
                hex(section['sh_size']),
                section['sh_type'],
                describe_sh_flags(section['sh_flags'])
            ])

        self.log('info', "ELF Sections:")
        self.log('table', dict(header=['Name', 'Addr', 'Size', 'Type', 'Flags'], rows=rows))

    def symbols(self):
        if not self.__check_session():
            return

        rows = []
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection): continue

            for cnt, symbol in enumerate(section.iter_symbols()):
                rows.append([
                    cnt,
                    hex(symbol['st_value']),
                    hex(symbol['st_size']),
                    describe_symbol_type(symbol['st_info']['type']),
                    symbol.name
                ])
        
        self.log('info', "ELF Symbols:")
        self.log('table', dict(header=['Num', 'Value', 'Size', 'Type', 'Name'], rows=rows))

    def interp(self):
        if not self.__check_session():
            return

        interp = None
        for segment in self.elf.iter_segments():
            if segment['p_type'] == 'PT_INTERP':
                interp = segment
                break
        if interp:
            self.log('', "Program interpreter: {0}".format(interp.get_interp_name()))
        else:
            self.log('error', "No PT_INTERP entry found")

    def dynamic(self):
        if not self.__check_session():
            return

        for section in self.elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                if tag.entry.d_tag != "DT_NEEDED": continue
                self.log('info', tag.needed)

    def usage(self):
        self.log('', "usage: elf <command>")

    def help(self):
        self.usage()
        self.log('', "")
        self.log('', "Options:")
        self.log('', "\thelp\t\tShow this help message")
        self.log('', "\tsections\tList ELF sections")
        self.log('', "\tsegments\tList ELF segments")
        self.log('', "\tsymbols\t\tList ELF symbols")
        self.log('', "\tinterp\t\tGet the program interpreter")
        self.log('', "\tdynamic\t\tShow the dynamic section")
        self.log('', "")

    def run(self):
        if not HAVE_ELFTOOLS:
            self.log('error', "Missing dependency, install pyelftools (`pip install pyelftools")
            return

        if len(self.args) == 0:
            self.help()
            return

        if self.args[0] == 'help':
            self.help()
        elif self.args[0] == 'sections':
            self.sections()
        elif self.args[0] == 'segments':
            self.segments()
        elif self.args[0] == 'symbols':
            self.symbols()
        elif self.args[0] == 'interp':
            self.interp()
        elif self.args[0] == 'dynamic':
            self.dynamic()
