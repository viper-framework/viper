# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import getopt
import hashlib
import datetime
import tempfile
import re

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.descriptions import describe_sh_flags 
    from elftools.elf.descriptions import describe_p_flags
    from elftools.elf.descriptions import describe_symbol_type
    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

from viper.common.out import *
from viper.common.objects import File
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.storage import get_sample_path
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
            print_error("No session opened")
            return False

        if not self.elf:
            try:
                fd = open(__sessions__.current.file.path, 'rb')
                self.elf = ELFFile(fd)
            except:
                print_error("Unable to parse ELF file")
                return False

        return True

    def segments(self):
        if not self.__check_session():
            return
        
        rows = []
        for segment in self.elf.iter_segments():
            rows.append([segment['p_type'],
                         segment['p_vaddr'],
                         hex(segment['p_filesz']),
                         hex(segment['p_memsz']),
                         describe_p_flags(segment['p_flags'])
                         ])
                         
        print_info("ELF Segments:") 
        print(table(header=['Type', 'VirtAddr', 'FileSize', 'MemSize', 'Flags'], rows=rows))

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

        print_info("ELF Sections:")
        print(table(header=['Name', 'Addr', 'Size', 'Type', 'Flags'], rows=rows))

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
        
        print_info("ELF Symbols:")
        print(table(header=['Num', 'Value', 'Size', 'Type', 'Name'], rows=rows))

    def usage(self):
        print("usage: elf <command>")

    def help(self):
        self.usage()
        print("")
        print("Options:")
        print("\thelp\t\tShow this help message")
        print("\tsections\t\tList ELF sections")
        print("\tsegments\t\tList ELF segments")
        print("\tsymbols\t\tList ELF symbols")
        print("")

    def run(self):
        if not HAVE_ELFTOOLS:
            print_error("Missing dependency, install pyelftools (`pip install pyelftools")
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
