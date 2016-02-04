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


class MachODYLDInfoCommand(MachOLoadCommand):

    rebase_off = 0
    rebase_size = 0
    bind_off = 0
    bind_size = 0
    weak_bind_off = 0
    weak_bind_size = 0
    lazy_bind_off = 0
    lazy_bind_size = 0
    export_off = 0
    export_size = 0

    def __init__(self, macho_file=None, cmd=0):
        self.cmd = cmd
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.rebase_off, self.rebase_size, self.bind_off, self.bind_size = unpack('<IIII', macho_file.read(4*4))
        self.weak_bind_off, self.weak_bind_size, self.lazy_bind_off, self.lazy_bind_size = unpack('<IIII', macho_file.read(4*4))
        self.export_off, self.export_size = unpack('<II', macho_file.read(2*4))

    def write(self, macho_file):
        before = macho_file.tell()
        macho_file.write(pack('<I', self.cmd))
        macho_file.write(pack('<I', 0x0)) # cmdsize
        macho_file.write(pack('<IIII', self.rebase_off, self.rebase_size, self.bind_off, self.bind_size))
        macho_file.write(pack('<IIII', self.weak_bind_off, self.weak_bind_size, self.lazy_bind_off, self.lazy_bind_size))
        macho_file.write(pack('<II', self.export_off, self.export_size))
        after = macho_file.tell()
        macho_file.seek(before+4)
        macho_file.write(pack('<I', after-before))
        macho_file.seek(after)

    def display(self, before=''):
        print before + green("[+]")+" %s" % ("LC_DYLD_INFO_ONLY" if self.cmd == LC_DYLD_INFO_ONLY else "LC_DYLD_INFO")
        print before + "\t- rebase_off : 0x%x" % self.rebase_off
        print before + "\t- rebase_size : %d (0x%x)" % (self.rebase_size, self.rebase_size)
        print before + "\t- bind_off : 0x%x" % self.bind_off
        print before + "\t- bind_size : %d (0x%x)" % (self.bind_size, self.bind_size)
        print before + "\t- weak_bind_off : 0x%x" % self.weak_bind_off
        print before + "\t- weak_bind_size : %d (0x%x)" % (self.weak_bind_size, self.weak_bind_size)
        print before + "\t- lazy_bind_off : 0x%x" % self.lazy_bind_off
        print before + "\t- lazy_bind_size : %d (0x%x)" % (self.lazy_bind_size, self.lazy_bind_size)
        print before + "\t- export_off : 0x%x" % self.export_off
        print before + "\t- export_size : %d (0x%x)" % (self.export_size, self.export_size)
