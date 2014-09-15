# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import getopt
import hashlib
import datetime
import tempfile
import re

try:
    import elftools
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


class PE(Module):
    cmd = 'elf'
    description = 'Extract information from ELF headers'
    authors = ['emdel']

    def __init__(self):
        self.elf = None

    def __check_session(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return False

        if not self.pe:
            try:
                self.elf = elftools.elf.elffile(__sessions__.current.file.get_fd())
            except:
                print_error("Unable to parse PE file")
                return False

        return True

    def __get_filetype(self, data):
        if not HAVE_MAGIC:
            return None

        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.buffer(data)
        except:
            try:
                file_type = magic.from_buffer(data)
            except Exception:
                return None

        return file_type

    def __get_md5(self, data):
        md5 = hashlib.md5()
        md5.update(data)
        return md5.hexdigest()

    def sections(self):
        if not self.__check_session():
            return

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    print_info("DLL: {0}".format(entry.dll))
                    for symbol in entry.imports:
                        print_item("{0}: {1}".format(hex(symbol.address), symbol.name), tabs=1)
                except:
                    continue
    
    def segments(self):
        if not self.__check_session():
            return
        
        print_info("Exports:")
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print_item("{0}: {1} ({2})".format(hex(self.pe.OPTIONAL_HEADER.ImageBase + symbol.address), symbol.name, symbol.ordinal), tabs=1)
    
    
    def sections(self):
        if not self.__check_session():
            return

        rows = []
        for section in self.pe.sections:
            rows.append([
                section.Name,
                hex(section.VirtualAddress),
                hex(section.Misc_VirtualSize),
                section.SizeOfRawData,
                section.get_entropy()
            ])

        print_info("PE Sections:")
        print(table(header=['Name', 'RVA', 'VirtualSize', 'RawDataSize', 'Entropy'], rows=rows))

    def usage(self):
        print("usage: pe <command>")

    def help(self):
        self.usage()
        print("")
        print("Options:")
        print("\thelp\t\tShow this help message")
        print("\tsections\t\tList ELF sections")
        print("\tsegments\t\tList ELF segments")
        print("")

    def run(self):
        if not HAVE_ELFTOOLS:
            print_error("Missing dependency, install pefile (`pip install pefile`)")
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
