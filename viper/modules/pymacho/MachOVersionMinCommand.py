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
from viper.modules.pymacho.Utils import int32_to_version, green
from viper.modules.pymacho.Constants import *


class MachOVersionMinCommand(MachOLoadCommand):

    version = 0
    sdk = 0

    def __init__(self, macho_file=None, cmd=0):
        self.cmd = cmd
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.version, self.sdk = unpack('<II', macho_file.read(4*2))

    def write(self, macho_file):
        before = macho_file.tell()
        macho_file.write(pack('<II', self.cmd, 0x0))
        macho_file.write(pack('<II', self.version, self.sdk))
        after = macho_file.tell()
        macho_file.seek(before+4)
        macho_file.write(pack('<I', after-before))
        macho_file.seek(after)

    def display(self, before=''):
        print before + green("[+]")+" %s" % ("LC_VERSION_MIN_MACOSX" if self.cmd == LC_VERSION_MIN_MACOSX else "LC_VERSION_MIN_IPHONEOS")
        print before + "\t- version : %s" % int32_to_version(self.version)
        print before + "\t- sdk : %s" % int32_to_version(self.sdk)
