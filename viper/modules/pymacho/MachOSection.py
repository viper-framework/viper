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
from viper.modules.pymacho.Constants import *
from viper.modules.pymacho.MachORelocationInfo import MachORelocationInfo
from viper.modules.pymacho.Utils import green


class MachOSection(object):

    arch = 32
    sectname = ""
    segname = ""
    addr = 0
    size = 0
    offset = 0
    align = 0
    reloff = 0
    nreloc = 0
    flags = 0
    reserved1 = 0
    reserved2 = 0

    def __init__(self, macho_file=None, arch=32):
        if arch != 32:
            self.arch = 64
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.sectname = "".join(char if char != "\x00" else "" for char in unpack("<cccccccccccccccc", macho_file.read(16)))
        self.segname = "".join(char if char != "\x00" else "" for char in unpack("<cccccccccccccccc", macho_file.read(16)))

        if self.arch == 32:
            self.addr, self.size = unpack('<II', macho_file.read(2*4))
        else:
            self.addr, self.size = unpack('<QQ', macho_file.read(8*2))

        self.offset, self.align, self.reloff, self.nreloc = unpack('<IIII', macho_file.read(4*4))
        self.flags, self.reserved1, self.reserved2 = unpack('<III', macho_file.read(3*4))

        if self.arch == 64:
            self.reserved3 = unpack('<I', macho_file.read(4))[0]
        before = macho_file.tell()
        # get data
        macho_file.seek(self.offset)
        self.data = macho_file.read(self.size)
        # go to relocation offset
        macho_file.seek(self.reloff)
        self.relocs = []
        for i in range(self.nreloc):
            self.relocs.append(MachORelocationInfo(macho_file))
        macho_file.seek(before)

    def write(self, macho_file):
        macho_file.write(pack('<16s', self.sectname))
        macho_file.write(pack('<16s', self.segname))
        if self.arch == 32:
            macho_file.write(pack('<II', self.addr, self.size))
        else:
            macho_file.write(pack('<QQ', self.addr, self.size))
        macho_file.write(pack('<IIII', self.offset, self.align, self.reloff, self.nreloc))
        macho_file.write(pack('<III', self.flags, self.reserved1, self.reserved2))
        if self.arch == 64:
            macho_file.write(pack('<I', self.reserved3))
        # now write data and reloc
        before = macho_file.tell()
        macho_file.seek(self.offset)
        add = "\x90" * (self.align - self.size%self.align) if self.align != 0 and self.sectname == "__text" else ""
        macho_file.write(self.data + add) # must be align to self.align
        macho_file.seek(self.reloff)
        for reloc in self.relocs:
            reloc.write(macho_file)
        macho_file.seek(before)

    def display_flags(self):
        """
        From apple source code :
        /*
         * The flags field of a section structure is separated into two parts a section
         * type and section attributes.  The section types are mutually exclusive (it
         * can only have one type) but the section attributes are not (it may have more
         * than one attribute).
         */
        """
        rflags = []
        stype = self.flags & 0xff
        attributes = self.flags & 0xffffff00
        if stype & S_REGULAR:
            rflags.append("S_REGULAR")
            stype &= ~S_REGULAR
        if stype & S_ZEROFILL:
            rflags.append("S_ZEROFILL")
            stype &= ~S_ZEROFILL
        if stype & S_CSTRING_LITERALS:
            rflags.append("S_CSTRING_LITERALS")
            stype &= ~S_CSTRING_LITERALS
        if stype & S_4BYTE_LITERALS:
            rflags.append("S_4BYTE_LITERALS")
            stype &= ~S_4BYTE_LITERALS
        if stype & S_8BYTE_LITERALS:
            rflags.append("S_8BYTE_LITERALS")
            stype &= ~S_8BYTE_LITERALS
        if stype & S_LITERAL_POINTERS:
            rflags.append("S_LITERAL_POINTERS")
            stype &= ~S_LITERAL_POINTERS
        if stype & S_NON_LAZY_SYMBOL_POINTERS:
            rflags.append("S_NON_LAZY_SYMBOL_POINTERS")
            stype &= ~S_NON_LAZY_SYMBOL_POINTERS
        if stype & S_LAZY_SYMBOL_POINTERS:
            rflags.append("S_LAZY_SYMBOL_POINTERS")
            stype &= ~S_LAZY_SYMBOL_POINTERS
        if stype & S_SYMBOL_STUBS:
            rflags.append("S_SYMBOL_STUBS")
            stype &= ~S_SYMBOL_STUBS
        if stype & S_MOD_INIT_FUNC_POINTERS:
            rflags.append("S_MOD_INIT_FUNC_POINTERS")
            stype &= ~S_MOD_INIT_FUNC_POINTERS
        if stype & S_MOD_TERM_FUNC_POINTERS:
            rflags.append("S_MOD_TERM_FUNC_POINTERS")
            stype &= ~S_MOD_TERM_FUNC_POINTERS
        if stype & S_COALESCED:
            rflags.append("S_COALESCED")
            stype &= ~S_COALESCED
        if stype & S_GB_ZEROFILL:
            rflags.append("S_GB_ZEROFILL")
            stype &= ~S_GB_ZEROFILL
        if stype & S_INTERPOSING:
            rflags.append("S_INTERPOSING")
            stype &= ~S_INTERPOSING
        if stype & S_16BYTE_LITERALS:
            rflags.append("S_16BYTE_LITERALS")
            stype &= ~S_16BYTE_LITERALS
        if stype & S_DTRACE_DOF:
            rflags.append("S_DTRACE_DOF")
            stype &= ~S_DTRACE_DOF
        if stype & S_LAZY_DYLIB_SYMBOL_POINTERS:
            rflags.append("S_LAZY_DYLIB_SYMBOL_POINTERS")
            stype &= ~S_LAZY_DYLIB_SYMBOL_POINTERS
        if stype & S_THREAD_LOCAL_REGULAR:
            rflags.append("S_THREAD_LOCAL_REGULAR")
            stype &= ~S_THREAD_LOCAL_REGULAR
        if stype & S_THREAD_LOCAL_ZEROFILL:
            rflags.append("S_THREAD_LOCAL_ZEROFILL")
            stype &= ~S_THREAD_LOCAL_ZEROFILL
        if stype & S_THREAD_LOCAL_VARIABLES:
            rflags.append("S_THREAD_LOCAL_VARIABLES")
            stype &= ~S_THREAD_LOCAL_VARIABLES
        if stype & S_THREAD_LOCAL_VARIABLE_POINTERS:
            rflags.append("S_THREAD_LOCAL_VARIABLE_POINTERS")
            stype &= ~S_THREAD_LOCAL_VARIABLE_POINTERS
        if stype & S_THREAD_LOCAL_INIT_FUNCTION_POINTERS:
            rflags.append("S_THREAD_LOCAL_INIT_FUNCTION_POINTERS")
            stype &= ~S_THREAD_LOCAL_INIT_FUNCTION_POINTERS
        if attributes & SECTION_ATTRIBUTES_USR:
            rflags.append("SECTION_ATTRIBUTES_USR")
            attributes &= ~SECTION_ATTRIBUTES_USR
        if attributes & S_ATTR_PURE_INSTRUCTIONS:
            rflags.append("S_ATTR_PURE_INSTRUCTIONS")
            attributes &= ~S_ATTR_PURE_INSTRUCTIONS
        if attributes & S_ATTR_NO_TOC:
            rflags.append("S_ATTR_NO_TOC")
            attributes &= ~S_ATTR_NO_TOC
        if attributes & S_ATTR_STRIP_STATIC_SYMS:
            rflags.append("S_ATTR_STRIP_STATIC_SYMS")
            attributes &= ~S_ATTR_STRIP_STATIC_SYMS
        if attributes & S_ATTR_NO_DEAD_STRIP:
            rflags.append("S_ATTR_NO_DEAD_STRIP")
            attributes &= ~S_ATTR_NO_DEAD_STRIP
        if attributes & S_ATTR_LIVE_SUPPORT:
            rflags.append("S_ATTR_LIVE_SUPPORT")
            attributes &= ~S_ATTR_LIVE_SUPPORT
        if attributes & S_ATTR_SELF_MODIFYING_CODE:
            rflags.append("S_ATTR_SELF_MODIFYING_CODE")
            attributes &= ~S_ATTR_SELF_MODIFYING_CODE
        if attributes & S_ATTR_DEBUG:
            rflags.append("S_ATTR_DEBUG")
            attributes &= ~S_ATTR_DEBUG
        if attributes & SECTION_ATTRIBUTES_SYS:
            rflags.append("SECTION_ATTRIBUTES_SYS")
            attributes &= ~SECTION_ATTRIBUTES_SYS
        if attributes & S_ATTR_SOME_INSTRUCTIONS:
            rflags.append("S_ATTR_SOME_INSTRUCTIONS")
            attributes &= ~S_ATTR_SOME_INSTRUCTIONS
        if attributes & S_ATTR_LOC_RELOC:
            rflags.append("S_ATTR_LOC_RELOC")
            attributes &= ~S_ATTR_LOC_RELOC
        return rflags

    def display(self, before=''):
        print before + green("[+]")+" %s" % self.sectname
        print before + "\t- addr :0x%x" % self.addr
        print before + "\t- size : 0x%x" % self.size
        print before + "\t- offset : 0x%x" % self.offset
        print before + "\t- align : 0x%x" % self.align
        print before + "\t- reloff : 0x%x" % self.reloff
        print before + "\t- nreloc : 0x%x" % self.nreloc
        print before + "\t- flags : 0x%x - %s" % (self.flags, ", ".join(self.display_flags()))
        print before + "\t- reserved1 : 0x%x" % self.reserved1
        print before + "\t- reserved2 : 0x%x" % self.reserved2
        if self.arch != 32:
            print before + "\t- reserved3 : 0x%x" % self.reserved3
