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


class MachOHeader(object):
    """
    Represent a Mach-O Header
    """

    magic = 0
    cputype = 0
    cpusubtype = 0
    filetype = 0
    ncmds = 0
    sizeofcmds = 0
    flags = 0

    def __init__(self, macho_file=None):
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        """
        Parse headers from macho_file.
        """
        assert macho_file.tell() == 0
        self.magic = unpack('<I', macho_file.read(4))[0]
        assert self.magic in [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64]
        self.cputype, self.cpusubtype, self.filetype = unpack("<III", macho_file.read(4*3))
        self.ncmds, self.sizeofcmds, self.flags = unpack('<III', macho_file.read(4*3))
        if self.is_64() is True:
            self.reserved = unpack('<I', macho_file.read(4))[0]

    def write(self, macho_file):
        macho_file.seek(0)
        macho_file.write(pack('<IIII', self.magic, self.cputype, self.cpusubtype, self.filetype))
        macho_file.write(pack('<III', self.ncmds, self.sizeofcmds, self.flags))
        if self.is_64():
            macho_file.write(pack('<I', self.reserved))

    def is_64(self):
        """
        Return True if the magic number says 'I am a 64 mach-o file', False in others cases.
        """
        return (self.magic == MH_MAGIC_64 or self.magic == MH_CIGAM_64)

    def display_magic(self):
        """
        Return the string to display based on its magic number.
        """
        if self.is_64() is True:
            return "64 bits"
        else:
            return "32 bits"

    def display_cputype(self):
        """
        Return the string to display based on its cputype number.
        """
        if self.cputype == CPU_TYPE_POWERPC:
            return "ppc"
        elif self.cputype == CPU_TYPE_POWERPC64:
            return "ppc64"
        elif self.cputype == CPU_TYPE_I386:
            return "i386"
        elif self.cputype == CPU_TYPE_X86_64:
            return "x86_64"
        elif self.cputype == CPU_TYPE_MC680x0:
            return "m68k"
        elif self.cputype == CPU_TYPE_HPPA:
            return "hppa"
        elif self.cputype == CPU_TYPE_I860:
            return "i860"
        elif self.cputype == CPU_TYPE_MC88000:
            return "m88k"
        elif self.cputype == CPU_TYPE_SPARC:
            return "sparc"
        else:
            return "unknow arch"

    def display_filetype(self):
        """
        Return the string to display based on its filetype number.
        """
        if self.filetype == MH_OBJECT:
            return "relocatable object file"
        elif self.filetype == MH_EXECUTE:
            return "executable file"
        elif self.filetype == MH_FVMLIB:
            return "fixed VM shared library file"
        elif self.filetype == MH_CORE:
            return "core file"
        elif self.filetype == MH_PRELOAD:
            return "preloaded executable file"
        elif self.filetype == MH_DYLIB:
            return "dynamically bound shared library"
        elif self.filetype == MH_DYLINKER:
            return "dynamic link editor"
        elif self.filetype == MH_BUNDLE:
            return "dynamically bound bundle file"
        elif self.filetype == MH_DYLIB_STUB:
            return "shared library stub for static linking only, no section contents"
        elif self.filetype == MH_DSYM:
            return "companion file with only debug sections"
        elif self.filetype == MH_KEXT_BUNDLE:
            return "x86_64 kernel extension"
        else:
            return "unknow filetype"

    def display_flags(self):
        rflags = []
        flags = self.flags
        if flags & MH_NOUNDEFS:
            rflags.append("NOUNDEFS")
            flags &= ~MH_NOUNDEFS
        if flags & MH_INCRLINK:
            rflags.append("INCRLINK")
            flags &= ~MH_INCRLINK
        if flags & MH_DYLDLINK:
            rflags.append("DYLDLINK")
            flags &= ~MH_DYLDLINK
        if flags & MH_BINDATLOAD:
            rflags.append("BINDATLOAD")
            flags &= ~MH_BINDATLOAD
        if flags & MH_PREBOUND:
            rflags.append("PREBOUND")
            flags &= ~MH_PREBOUND
        if flags & MH_SPLIT_SEGS:
            rflags.append("SPLIT_SEGS")
            flags &= ~MH_SPLIT_SEGS
        if flags & MH_LAZY_INIT:
            rflags.append("LAZY_INIT")
            flags &= ~MH_LAZY_INIT
        if flags & MH_TWOLEVEL:
            rflags.append("TWOLEVEL")
            flags &= ~MH_TWOLEVEL
        if flags & MH_FORCE_FLAT:
            rflags.append("FORCE_FLAT")
            flags &= ~MH_FORCE_FLAT
        if flags & MH_NOMULTIDEFS:
            rflags.append("NOMULTIDEFS")
            flags &= ~MH_NOMULTIDEFS
        if flags & MH_NOFIXPREBINDING:
            rflags.append("NOFIXPREBINDING")
            flags &= ~MH_NOFIXPREBINDING
        if flags & MH_PREBINDABLE:
            rflags.append("PREBINDABLE")
            flags &= ~MH_PREBINDABLE
        if flags & MH_ALLMODSBOUND:
            rflags.append("ALLMODSBOUND")
            flags &= ~MH_ALLMODSBOUND
        if flags & MH_SUBSECTIONS_VIA_SYMBOLS:
            rflags.append("SUBSECTIONS_VIA_SYMBOLS")
            flags &= ~MH_SUBSECTIONS_VIA_SYMBOLS
        if flags & MH_CANONICAL:
            rflags.append("CANONICAL")
            flags &= ~MH_CANONICAL
        if flags & MH_WEAK_DEFINES:
            rflags.append("WEAK_DEFINES")
            flags &= ~MH_WEAK_DEFINES
        if flags & MH_BINDS_TO_WEAK:
            rflags.append("BINDS_TO_WEAK")
            flags &= ~MH_BINDS_TO_WEAK
        if flags & MH_ALLOW_STACK_EXECUTION:
            rflags.append("ALLOW_STACK_EXECUTION")
            flags &= ~MH_ALLOW_STACK_EXECUTION
        if flags & MH_ROOT_SAFE:
            rflags.append("ROOT_SAFE")
            flags &= ~MH_ROOT_SAFE
        if flags & MH_SETUID_SAFE:
            rflags.append("SETUID_SAFE")
            flags &= ~MH_SETUID_SAFE
        if flags & MH_SETUID_SAFE:
            rflags.append("SETUID_SAFE")
            flags &= ~MH_SETUID_SAFE
        if flags & MH_NO_REEXPORTED_DYLIBS:
            rflags.append("NO_REEXPORTED_DYLIBS")
            flags &= ~MH_NO_REEXPORTED_DYLIBS
        if flags & MH_PIE:
            rflags.append("PIE")
            flags &= ~MH_PIE
        if flags & MH_DEAD_STRIPPABLE_DYLIB:
            rflags.append("DEAD_STRIPPABLE_DYLIB")
            flags &= ~MH_DEAD_STRIPPABLE_DYLIB
        if flags & MH_HAS_TLV_DESCRIPTORS:
            rflags.append("HAS_TLV_DESCRIPTORS")
            flags &= ~MH_HAS_TLV_DESCRIPTORS
        if flags & MH_NO_HEAP_EXECUTION:
            rflags.append("NO_HEAP_EXECUTION")
            flags &= ~MH_NO_HEAP_EXECUTION
        if flags != 0:
            raise Exception("flags is not 0 (0x%x) - some flags aren't known" % flags)
        return rflags
