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
from viper.modules.pymacho.Utils import green


class MachONList(object):

    n_strx = 0
    n_type = 0
    n_sect = 0
    n_desc = 0
    n_value = 0

    def __init__(self, macho_file=None, is_64=False):
        self.is_64 = is_64
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.n_strx = unpack('<I', macho_file.read(4))[0]
        self.n_type, self.n_sect, self.n_desc = unpack('<BBH', macho_file.read(4))
        if self.is_64 is False:
            self.n_value = unpack('<I', macho_file.read(4))[0]
        else:
            self.n_value = unpack('<Q', macho_file.read(8))[0]

    def write(self, macho_file):
        macho_file.write(pack('<IBBH', self.n_strx, self.n_type, self.n_sect, self.n_desc))
        if self.is_64 is True:
            macho_file.write(pack('<Q', self.n_value))
        else:
            macho_file.write(pack('<I', self.n_value))

    def display(self, before=''):
        print before + green("[+]")+" NList item :"
        print before + "\t- n_strx : 0x%08x" % self.n_strx
        print before + "\t- n_type : 0x%02x" % self.n_type
        print before + "\t- n_sect : 0x%02x" % self.n_sect
        print before + "\t- n_desc : 0x%04x" % self.n_desc
        print before + "\t- n_value : 0x%x" % self.n_value
