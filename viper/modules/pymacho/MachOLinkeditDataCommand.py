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


class MachOLinkeditDataCommand(MachOLoadCommand):

    dataoff = 0
    datasize = 0

    def __init__(self, macho_file=None, cmd=0):
        self.cmd = cmd
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.dataoff, self.datasize = unpack('<II', macho_file.read(4*2))
        before = macho_file.tell()
        macho_file.seek(self.dataoff)
        self.data = macho_file.read(self.datasize)
        macho_file.seek(before)

    def write(self, macho_file):
        before = macho_file.tell()
        macho_file.write(pack('<II', self.cmd, 0x0))
        macho_file.write(pack('<II', self.dataoff, self.datasize))
        after = macho_file.tell()
        macho_file.seek(self.dataoff)
        macho_file.write(self.data)
        macho_file.seek(before+4)
        macho_file.write(pack('<I', after-before))
        macho_file.seek(after)

    def display(self, before=''):
        name = ''
        if self.cmd == LC_CODE_SIGNATURE:
            name = 'LC_CODE_SIGNATURE'
        elif self.cmd == LC_SEGMENT_SPLIT_INFO:
            name = 'LC_SEGMENT_SPLIT_INFO'
        elif self.cmd == LC_FUNCTION_STARTS:
            name = 'LC_FUNCTION_STARTS'
        elif self.cmd == LC_DATA_IN_CODE:
            name = 'LC_DATA_IN_CODE'
        elif self.cmd == LC_DYLIB_CODE_SIGN_DRS:
            name = 'LC_DYLIB_CODE_SIGN_DRS'
        else:
            raise Exception('WHAT DA FUCK')

        print before + green("[+]")+" %s" % name
        print before + "\t- dataoff : 0x%x" % self.dataoff
        print before + "\t- datasize : 0x%x" % self.datasize
