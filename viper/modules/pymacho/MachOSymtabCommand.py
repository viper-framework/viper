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
from viper.modules.pymacho.MachONList import MachONList
from viper.modules.pymacho.Utils import green


class MachOSymtabCommand(MachOLoadCommand):

    symoff = 0
    nsyms = 0
    stroff = 0
    strsize = 0
    syms = None
    strs = None

    def __init__(self, macho_file=None, cmd=0, is_64=False):
        self.cmd = cmd
        self.syms = []
        self.strs = []
        self.is_64 = is_64
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.symoff, self.nsyms = unpack('<II', macho_file.read(4*2))
        self.stroff, self.strsize = unpack('<II', macho_file.read(4*2))
        before = macho_file.tell()
        # parse symoff
        macho_file.seek(self.symoff)
        for i in range(self.nsyms):
            self.syms.append(MachONList(macho_file, self.is_64))
        # parse strings
        macho_file.seek(self.stroff)
        chaines = unpack('<'+str(self.strsize)+'s', macho_file.read(self.strsize))[0]
        for chaine in chaines.split("\x00"):
                self.strs.append(chaine)
        macho_file.seek(before)

    def write(self, macho_file):
        before = macho_file.tell()
        macho_file.write(pack('<I', self.cmd))
        macho_file.write(pack('<I', 0x0)) # cmdsize
        macho_file.write(pack('<IIII', self.symoff, self.nsyms, self.stroff, self.strsize))
        after = macho_file.tell()
        macho_file.seek(self.symoff)
        for sym in self.syms:
            sym.write(macho_file)
        macho_file.seek(self.stroff)
        macho_file.write("\x00".join(self.strs))
        macho_file.seek(before+4)
        macho_file.write(pack('<I', after-before))
        macho_file.seek(after)

    def display(self, before=''):
        print before + green("[+]")+" LC_SYMTAB"
        print before + "\t- symoff : 0x%x" % self.symoff
        print before + "\t- nsyms : %d" % self.nsyms
        for sym in self.syms:
            sym.display(before=before+"\t")
        print before + "\t- stroff : 0x%x" % self.stroff
        print before + "\t- strsize : %d (0x%x)" % (self.strsize, self.strsize)
        print before + "\t- strings : "+str(self.strs)
