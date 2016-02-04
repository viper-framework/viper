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

from struct import unpack, pack
from viper.modules.pymacho.MachOLoadCommand import MachOLoadCommand
from viper.modules.pymacho.Constants import *
from viper.modules.pymacho.Utils import green


class MachODYLinkerCommand(MachOLoadCommand):

    offset = 0
    path = ""

    def __init__(self, macho_file=None, cmd=0, is_64=False):
        self.cmd = cmd
        if is_64 is True:
            self.align = 0x8
        else:
            self.align = 0x4
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        macho_file.seek(-4, 1)
        cmdsize = unpack('<I', macho_file.read(4))[0]
        # get the offset
        self.offset = unpack('<I', macho_file.read(4))[0]
        # get the string
        strlen = (cmdsize - self.offset)
        extract = "<%s" % ('s'*strlen)
        self.path = "".join(unpack(extract, macho_file.read(strlen)))

    def write(self, macho_file):
        before = macho_file.tell()
        macho_file.write(pack('<II', self.cmd, 0x0))
        macho_file.write(pack('<I', self.offset))
        extract = "<" + str(len(self.path)) + "s"
        macho_file.write(pack(extract, self.path))
        after = macho_file.tell()
        macho_file.seek(before+4)
        macho_file.write(pack('<I', after-before))
        macho_file.seek(after)

    def display(self, before=''):
        print before + green("[+]")+" %s" % ("LC_DYLD_ENVIRONMENT" if self.cmd == LC_DYLD_ENVIRONMENT else "LC_LOAD_DYLINKER")
        print before + "\t - path : %s" % self.path
