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
from datetime import datetime
from viper.modules.pymacho.MachOLoadCommand import MachOLoadCommand
from viper.modules.pymacho.Utils import int32_to_version, green
from viper.modules.pymacho.Constants import *


class MachOLoadDYLibCommand(MachOLoadCommand):

    name = ""
    name_offset = 0
    timestamp = 0
    current_version = 0
    compatibility_version = 0

    def __init__(self, macho_file=None, cmd=0):
        self.cmd = cmd
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        # get cmdsize
        macho_file.seek(-4, 1)
        cmdsize = unpack('<I', macho_file.read(4))[0]
        # get the offset of string
        self.name_offset = unpack('<I', macho_file.read(4))[0]
        self.timestamp = unpack('<I', macho_file.read(4))[0]
        self.current_version = unpack('<I', macho_file.read(4))[0]
        self.compatibility_version = unpack('<I', macho_file.read(4))[0]
        # get string
        strlen = cmdsize - self.name_offset
        extract = "<%s" % ('s'*strlen)
        self.name = "".join(unpack(extract, macho_file.read(strlen)))

    def write(self, macho_file):
        before = macho_file.tell()
        macho_file.write(pack('<II', self.cmd, 0x0))
        macho_file.write(pack('<I', self.name_offset))
        macho_file.write(pack('<I', self.timestamp))
        macho_file.write(pack('<I', self.current_version))
        macho_file.write(pack('<I', self.compatibility_version))
        extract = "<"+str(len(self.name))+"s"
        macho_file.write(pack(extract, self.name))
        after = macho_file.tell()
        macho_file.seek(before+4)
        macho_file.write(pack('<I', after-before))
        macho_file.seek(after)

    def display(self, before=''):
        name = ''
        if self.cmd == LC_LOAD_DYLIB:
            name = 'LC_LOAD_DYLIB'
        elif self.cmd == LC_LOAD_WEAK_DYLIB:
            name = 'LC_LOAD_WEAK_DYLIB'
        elif self.cmd == LC_REEXPORT_DYLIB:
            name = 'LC_REEXPORT_DYLIB'
        elif self.cmd == LC_ID_DYLIB:
            name = 'LC_ID_DYLIB'
        else:
            raise Exception('FUUUUUUUUU')

        print before + green("[+]")+" %s" % name
        print before + "\t- name : %s" % self.name
        print before + "\t- timestamp : %s" % datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        print before + "\t- current_version : %s" % int32_to_version(self.current_version)
        print before + "\t- compatibility_version : %s" % int32_to_version(self.compatibility_version)
