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
from viper.modules.pymacho.MachOLoadCommand import MachOLoadCommand
from viper.modules.pymacho.Utils import green


class MachOEncryptionInfoCommand(MachOLoadCommand):

    cryptoff = 0
    cryptsize = 0
    cryptid = 0

    def __init__(self, macho_file=None, cmd=0):
        self.cmd = cmd
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.cryptoff, self.cryptsize = unpack('<II', macho_file.read(4*2))
        self.cryptid = unpack('<I', macho_file.read(4))[0]

    def write(self, macho_file):
        before = macho_file.tell()
        macho_file.write(pack('<II', self.cmd, 0x0))
        macho_file.write(pack('<III', self.cryptoff, self.cryptsize, self.cryptid))
        after = macho_file.tell()
        macho_file.seek(before+4)
        macho_file.write(pack('<I', after-before))
        macho_file.seek(after)

    def display(self, before=''):
        print before + green("[+]")+" LC_ENCRYPTION_INFO"
        print before + "\t- cryptoff : 0x%x" % self.cryptoff
        print before + "\t- cryptsize : 0x%x" % self.cryptsize
        print before + "\t- crypptid : 0x%x" % self.cryptid
