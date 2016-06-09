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


class MachORelocationInfo(object):

    r_adrdess = 0
    uint32 = 0

    """
    struct relocation_info {
       int32_t	r_address;	/* offset in the section to what is being
    				   relocated */
       uint32_t     r_symbolnum:24,	/* symbol index if r_extern == 1 or section
    				   ordinal if r_extern == 0 */
    		r_pcrel:1, 	/* was relocated pc relative already */
    		r_length:2,	/* 0=byte, 1=word, 2=long, 3=quad */
    		r_extern:1,	/* does not include value of sym referenced */
    		r_type:4;	/* if not 0, machine specific relocation type */
    };
    """

    def __init__(self, macho_file=None):
        if macho_file is not None:
            self.parse(macho_file)

    def parse(self, macho_file):
        self.r_address, self.uint32 = unpack('<II', macho_file.read(4*2))

    def write(self, macho_file):
        macho_file.write(pack('<II', self.r_address, self.uint32))

    def display(self, before):
        print before + "<MachORelocationInfo>"
