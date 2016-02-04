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

def int32_to_version(version):
    # X.Y.Z is encoded in nibbles xxxx.yy.zz
    return "%d.%d.%d" % (version >> 16, (version >> 8)&0xff, version&0xff)

def int64_to_version(version):
    # A.B.C.D.E packed as a24.b10.c10.d10.e10
    return "%d.%d.%d.%d.%d" % (version >> 40, (version >> 30)&0x3ff, (version>>20)&0x3ff, (version>>10)&0x3ff, version&0x3ff)

def display_protection(prot):
    return "%s%s%s" % ("r" if (prot>>2)&0x1 == 1 else "-", "w" if (prot>>1)&0x1 == 1 else "-", "x" if prot&0x1 == 1 else "-")

# thanks to peda - https://github.com/longld/peda/blob/master/lib/utils.py#L95
def colorize(text, color=None, attrib=None):
    """
    Colorize text using ansicolor
    ref: https://github.com/hellman/libcolors/blob/master/libcolors.py
    """
    # ansicolor definitions
    COLORS = {"black": "30", "red": "31", "green": "32", "yellow": "33",
                "blue": "34", "purple": "35", "cyan": "36", "white": "37"}
    CATTRS = {"regular": "0", "bold": "1", "underline": "4", "strike": "9",
                "light": "1", "dark": "2", "invert": "7"}

    CPRE = '\033['
    CSUF = '\033[0m'

    ccode = ""
    if attrib:
        for attr in attrib.lower().split():
            attr = attr.strip(",+|")
            if attr in CATTRS:
                ccode += ";" + CATTRS[attr]
    if color in COLORS:
        ccode += ";" + COLORS[color]
    return CPRE + ccode + "m" + text + CSUF

def green(text, attrib=None):
    return colorize(text, "green", attrib)

def red(text, attrib=None):
    return colorize(text, "red", attrib)

def yellow(text, attrib=None):
    return colorize(text, "yellow", attrib)

def blue(text, attrib=None):
    return colorize(text, "blue", attrib)
