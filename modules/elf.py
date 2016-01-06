# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.descriptions import describe_sh_flags
    from elftools.elf.descriptions import describe_p_flags
    from elftools.elf.descriptions import describe_symbol_type
    from elftools.elf.dynamic import DynamicSection
    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False

from viper.common.abstracts import Module
from viper.core.session import __sessions__


# Have a look at scripts/readelf.py - pyelftools
class ELF(Module):
    cmd = 'elf'
    description = 'Extract information from ELF headers'
    authors = ['emdel']

    def __init__(self):
        super(ELF, self).__init__()
        self.parser.add_argument('--sections', action='store_true', help='List ELF sections')
        self.parser.add_argument('--segments', action='store_true', help='List ELF segments')
        self.parser.add_argument('--symbols', action='store_true', help='List ELF symbols')
        self.parser.add_argument('--interpreter', action='store_true', help='Get the program interpreter')
        self.parser.add_argument('--dynamic', action='store_true', help='Show the dynamic section')
        self.elf = None

    def __check_session(self):
        if not __sessions__.is_set():
            self.log('error', "No open session")
            return False

        if not self.elf:
            try:
                fd = open(__sessions__.current.file.path, 'rb')
                self.elf = ELFFile(fd)
            except Exception as e:
                self.log('error', "Unable to parse ELF file: {0}".format(e))
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
            if not isinstance(section, SymbolTableSection):
                continue

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

    def interpreter(self):
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
                if tag.entry.d_tag != "DT_NEEDED":
                    continue
                self.log('info', tag.needed)

    def run(self):
        super(ELF, self).run()
        if self.args is None:
            return

        if not HAVE_ELFTOOLS:
            self.log('error', "Missing dependency, install pyelftools (`pip install pyelftools`)")
            return

        if self.args.sections:
            self.sections()
        elif self.args.segments:
            self.segments()
        elif self.args.symbols:
            self.symbols()
        elif self.args.interpreter:
            self.interpreter()
        elif self.args.dynamic:
            self.dynamic()
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
