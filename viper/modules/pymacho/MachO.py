# encoding: utf-8

"""
Copyright 2013 Jérémie BOUTOILLE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

from struct import unpack
from viper.modules.pymacho.MachOHeader import MachOHeader
from viper.modules.pymacho.MachOSegment import MachOSegment
from viper.modules.pymacho.MachODYLDInfoCommand import MachODYLDInfoCommand
from viper.modules.pymacho.MachOSymtabCommand import MachOSymtabCommand
from viper.modules.pymacho.MachODYSymtabCommand import MachODYSymtabCommand
from viper.modules.pymacho.MachODYLinkerCommand import MachODYLinkerCommand
from viper.modules.pymacho.MachOUUIDCommand import MachOUUIDCommand
from viper.modules.pymacho.MachOVersionMinCommand import MachOVersionMinCommand
from viper.modules.pymacho.MachOThreadCommand import MachOThreadCommand
from viper.modules.pymacho.MachOMainCommand import MachOMainCommand
from viper.modules.pymacho.MachOLoadDYLibCommand import MachOLoadDYLibCommand
from viper.modules.pymacho.MachOLinkeditDataCommand import MachOLinkeditDataCommand
from viper.modules.pymacho.MachORPathCommand import MachORPathCommand
from viper.modules.pymacho.MachOSourceVersionCommand import MachOSourceVersionCommand
from viper.modules.pymacho.MachOEncryptionInfoCommand import MachOEncryptionInfoCommand
from viper.modules.pymacho.Constants import *


class MachO(object):
    """
    Represent a Mach-O file
    """

    header = None
    segments = None
    commands = None

    def __init__(self, filename=None):
        self.header = MachOHeader()
        self.segments = []
        self.commands = []
        if filename is not None:
            with open(filename, "rb") as macho_file:
                self.load_file(macho_file)

    def load_file(self, macho_file):
        self.header = MachOHeader(macho_file)
        self.load_commands(macho_file)

    def write_file(self, filename):
        with open(filename, "wb") as macho_file:
            self.header.write(macho_file)
            for segment in self.segments:
                segment.write(macho_file)
            for command in self.commands:
                command.write(macho_file)

    def load_commands(self, macho_file):
        assert macho_file.tell() == 28 or macho_file.tell() == 32
        for i in range(self.header.ncmds):
            cmd, cmdsize = unpack('<II', macho_file.read(4*2))
            if cmd == LC_SEGMENT:
                self.segments.append(MachOSegment(macho_file))
            elif cmd == LC_SEGMENT_64:
                self.segments.append(MachOSegment(macho_file, arch=64))
            elif cmd in [LC_DYLD_INFO_ONLY, LC_DYLD_INFO]:
                self.commands.append(MachODYLDInfoCommand(macho_file, cmd))
            elif cmd == LC_SYMTAB:
                self.commands.append(MachOSymtabCommand(macho_file, cmd, is_64=self.header.is_64()))
            elif cmd == LC_DYSYMTAB:
                self.commands.append(MachODYSymtabCommand(macho_file, cmd))
            elif cmd in [LC_LOAD_DYLINKER, LC_DYLD_ENVIRONMENT]:
                self.commands.append(MachODYLinkerCommand(macho_file, cmd, is_64=self.header.is_64()))
            elif cmd == LC_UUID:
                self.commands.append(MachOUUIDCommand(macho_file, cmd))
            elif cmd in [LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS]:
                self.commands.append(MachOVersionMinCommand(macho_file, cmd))
            elif cmd in [LC_UNIXTHREAD, LC_THREAD]:
                self.commands.append(MachOThreadCommand(macho_file, cmd))
            elif cmd == LC_MAIN:
                self.commands.append(MachOMainCommand(macho_file, cmd))
            elif cmd in [LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_ID_DYLIB]:
                self.commands.append(MachOLoadDYLibCommand(macho_file, cmd))
            elif cmd in [LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO, LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_DYLIB_CODE_SIGN_DRS]:
                self.commands.append(MachOLinkeditDataCommand(macho_file, cmd))
            elif cmd == LC_RPATH:
                self.commands.append(MachORPathCommand(macho_file, cmd))
            elif cmd == LC_SOURCE_VERSION:
                self.commands.append(MachOSourceVersionCommand(macho_file, cmd))
            elif cmd == LC_ENCRYPTION_INFO:
                self.commands.append(MachOEncryptionInfoCommand(macho_file, cmd))
            else:
                raise Exception("unknow load command : 0x%x - please report it!" % cmd)
