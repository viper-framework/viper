# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import getopt
import hashlib
import datetime
import tempfile
import re

try:
    from elftools.elf.elffile import ELFFile
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

        if not self.elf:
            try:
                fd = open(__sessions__.current.file.path, 'rb')
                self.elf = ELFFile(fd)
            except:
                print_error("Unable to parse ELF file")
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

    
    def segments(self):
        if not self.__check_session():
            return
        
        rows = []
        for segment in self.elf.iter_segments():
            rows.append([segment['p_type'],
                         segment['p_vaddr'],
                         segment['p_filesz'],
                         segment['p_memsz'],
                         segment['p_flags']
                         ])
                         
        print_info("ELF Segments:") 
        print(table(header=['Type', 'VirtAddr', 'FileSize', 'MemSize', 'Flags'], rows=rows))

    def sections(self):
        if not self.__check_session():
            return

        rows = []
        for section in self.elf.iter_sections():
            rows.append([
                section.name,
                hex(section['sh_addr']), 
                hex(section['sh_size']),
                section['sh_type'],
                section['sh_flags'],
                0
                #section.get_entropy()
            ])

        print_info("ELF Sections:")
        print(table(header=['Name', 'Addr', 'Size', 'Type', 'Flags', 'Entropy'], rows=rows))

    def usage(self):
        print("usage: elf <command>")

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
            print_error("Missing dependency, install pyelftools")
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
