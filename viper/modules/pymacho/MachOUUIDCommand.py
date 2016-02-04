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
from viper.modules.pymacho.Utils import green


class MachOUUIDCommand(MachOLoadCommand):

    uuid = ()

    def __init__(self, macho_file=None, cmd=0):
        self.cmd = cmd
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.uuid = unpack("<BBBBBBBBBBBBBBBB", macho_file.read(16))

    def write(self, macho_file):
        before = macho_file.tell()
        macho_file.write(pack('<II', self.cmd, 0x0))
        macho_file.write(pack('<BBBBBBBBBBBBBBBB', self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3], self.uuid[4], self.uuid[5], self.uuid[6], \
            self.uuid[7], self.uuid[8], self.uuid[9], self.uuid[10], self.uuid[11], self.uuid[12], \
            self.uuid[13], self.uuid[14], self.uuid[15]))
        after = macho_file.tell()
        macho_file.seek(before+4)
        macho_file.write(pack('<I', after-before))
        macho_file.seek(after)

    def display(self, before=''):
        print before + green("[+]")+" LC_UUID"
        print before + "\t- uuid : %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X" \
            % (self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3], self.uuid[4], self.uuid[5], self.uuid[6], \
            self.uuid[7], self.uuid[8], self.uuid[9], self.uuid[10], self.uuid[11], self.uuid[12], \
            self.uuid[13], self.uuid[14], self.uuid[15])
