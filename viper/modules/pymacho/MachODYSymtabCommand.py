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


class MachODYSymtabCommand(MachOLoadCommand):

    ilocalsym = 0
    nlocalsym = 0
    iextdefsym = 0
    nextdefsym = 0
    iundefsym = 0
    nundefsym = 0
    tocoff = 0
    ntoc = 0
    modtaboff = 0
    nmodtab = 0
    extrefsymoff = 0
    nextrefsym = 0
    indirectsymoff = 0
    nindirectsyms = 0
    extreloff = 0
    nextrel = 0
    locreloff = 0
    nlocrel = 0

    def __init__(self, macho_file=None, cmd=0):
        self.cmd = cmd
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.ilocalsym, self.nlocalsym = unpack('<II', macho_file.read(4*2))
        self.iextdefsym, self.nextdefsym = unpack('<II', macho_file.read(4*2))
        self.iundefsym, self.nundefsym = unpack('<II', macho_file.read(4*2))
        self.tocoff, self.ntoc = unpack('<II', macho_file.read(4*2))
        self.modtaboff, self.nmodtab = unpack('<II', macho_file.read(4*2))
        self.extrefsymoff, self.nextrefsym = unpack('<II', macho_file.read(4*2))
        self.indirectsymoff, self.nindirectsyms = unpack('<II', macho_file.read(4*2))
        self.extreloff, self.nextrel = unpack('<II', macho_file.read(4*2))
        self.locreloff, self.nlocrel = unpack('<II', macho_file.read(4*2))

    def write(self, macho_file):
        before = macho_file.tell()
        macho_file.write(pack('<II', self.cmd, 0x0))
        macho_file.write(pack('<II', self.ilocalsym, self.nlocalsym))
        macho_file.write(pack('<II', self.iextdefsym, self.nextdefsym))
        macho_file.write(pack('<II', self.iundefsym, self.nundefsym))
        macho_file.write(pack('<II', self.tocoff, self.ntoc))
        macho_file.write(pack('<II', self.modtaboff, self.nmodtab))
        macho_file.write(pack('<II', self.extrefsymoff, self.nextrefsym))
        macho_file.write(pack('<II', self.indirectsymoff, self.nindirectsyms))
        macho_file.write(pack('<II', self.extreloff, self.nextrel))
        macho_file.write(pack('<II', self.locreloff, self.nlocrel))
        after = macho_file.tell()
        macho_file.seek(before+4)
        macho_file.write(pack('<I', after-before))
        macho_file.seek(after)

    def display(self, before=''):
        print before + green("[+]")+" LC_DYSYMTAB"
        print before + "\t- ilocalsym : 0x%x" % self.ilocalsym
        print before + "\t- nlocalsym : 0x%x" % self.nlocalsym
        print before + "\t- iextdefsym : 0x%x" % self.iextdefsym
        print before + "\t- nextdefsym : 0x%x" % self.nextdefsym
        print before + "\t- iundefsym : 0x%x" % self.iundefsym
        print before + "\t- nundefsym : 0x%x" % self.nundefsym
        print before + "\t- tocoff : 0x%x" % self.tocoff
        print before + "\t- ntoc : %d" % self.ntoc
        print before + "\t- modtaboff : 0x%x" % self.modtaboff
        print before + "\t- nmodtab : 0x%x" % self.nmodtab
        print before + "\t- extrefsymoff : 0x%x" % self.extrefsymoff
        print before + "\t- nextrefsym : 0x%x" % self.nextrefsym
        print before + "\t- indirectsymoff : 0x%x" % self.indirectsymoff
        print before + "\t- nindirectsyms : 0x%x" % self.nindirectsyms
        print before + "\t- extreloff : 0x%x" % self.extreloff
        print before + "\t- nextrel : 0x%x" % self.nextrel
        print before + "\t- locreloff : 0x%x" % self.locreloff
        print before + "\t- nlocrel : 0x%x" % self.nlocrel
