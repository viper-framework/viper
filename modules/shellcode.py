# Copyright (C) 2014 Kevin Breen.
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import re

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__


class shellcode(Module):
    cmd = 'shellcode'
    description = 'Search For Known ShellCode'

    def run(self):
        if not __session__.is_set():
            print_error("No session opened")
            return

        data = open(__session__.file.path, 'rb').read()
        print_info("Searching for Possible ShellCode")

        # First Search Looks at raw text
        search = re.search(b'\x64\xa1\x30\x00|\x64\x8b\x0d\x30|\x64\x8b\x0d\x30|\x64\x8b\x15\x30|\x64\x8b\x35\x30|\x64\x8b\x3d\x30|\x6a\x30.\x64\x8b|\x33..\xb3\x64\x8b', data)
        if search is not None:
            print_info("FS:[30h] Shellcode Matched at offset {0}".format(hex(search.start())))
            
        search = re.search(b'\x64\x8b\x1d|\x64\xa1\x00|\x64\x8b\x0d|\x64\x8b\x15|\x64\x8b\x35|\x64\x8b\x3d', data)
        if search is not None:
            print_info("FS:[00h] Shellcode Matched at offset {0}".format(hex(search.start())))

        search = re.search(b'\x74.\xc1.\x0d\x03|\x74.\xc1.\x07\x03', data)
        if search is not None:
            print_info("API Hashing signature Matched at offset {0}".format(hex(search.start())))

        search = re.search(b'\x00\xff\x75\x00\xff\x55', data)
        if search is not None:
            print_info("PUSH DWORD[]/CALL[] Matched at offset {0}".format(hex(search.start())))
            
        search = re.search(b'\x00\xd9\x00\xee\x00\xd9\x74\x24\x00\xf4\x00\x00', data)
        if search is not None:
            print_info("FLDZ/FSTENV [esp-12] signature Matched at offset {0}".format(hex(search.start())))

        search = re.search(b'\x00\xe8\x00\x00\x00\x00\x58|\x59|\x5a|\x5b|\x5e|\x5f|\x5d\x00\x00', data)
        if search is not None:
            print_info("CALL next/POP signature Matched at offset {0}".format(hex(search.start())))
            
        search = re.search(b'\x55\x8b\x00\xec\x83\x00\xc4|\x55\x8b\x0ec\x81\x00\xec|\x55\x8b\x00\xec\x8b|\x55\x8b\x00\xec\xe8|\x55\x8b\x00\xec\xe9', data)
        if search is not None:
            print_info("Function prolog Matched at offset {0}".format(hex(search.start())))

        # This set of searches will match if the hex is stored as a string instead of bytes e.g. as a stream in an RTF File
        fs30search = re.search('64a13000|648b0d30|648b0d30|648b1530|648b3530|648b3d30|6a30..648b|33....b3648b', data)
        if fs30search is not None:
            print_info("FS:[30h] Shellcode Matched at offset {0}".format(hex(fs30search.start())))
            
        fs00search = re.search('648b1d00|64a10000|648b0d00|648b1500|648b3500|648b3d00', data)
        if fs00search is not None:
            print_info("FS:[00h] Shellcode Matched at offset {0}".format(hex(fs00search.start())))

        apisearch = re.search('74..c1..0d03|74..c1..0703', data)
        if apisearch is not None:
            print_info("API Hashing signature Matched at offset {0}".format(hex(apisearch.start())))

        pushsearch = re.search('00ff7500ff55', data)
        if pushsearch is not None:
            print_info("PUSH DWORD[]/CALL[] Matched at offset {0}".format(hex(pushsearch.start())))
            
        fldsearch = re.search('00d900ee00d9742400f40000', data)
        if fldsearch is not None:
            print_info("FLDZ/FSTENV [esp-12] signature Matched at offset {0}".format(hex(fldsearch.start())))

        popsearch = re.search('00e80000000058|59|5a|5b|5e|5f|5d0000', data)
        if popsearch is not None:
            print_info("CALL next/POP signature Matched at offset {0}".format(hex(popsearch.start())))
            
        prosearch = re.search('558b00ec8300c4|558b0ec8100ec|558b00ec8b|558b00ece8|558b00ece9', data)
        if prosearch is not None:
            print_info("Function prolog Matched at offset {0}".format(hex(prosearch.start())))
            
            
            
