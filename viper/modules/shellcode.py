# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import re

from viper.common.out import cyan
from viper.common.utils import hexdump
from viper.common.abstracts import Module
from viper.core.session import __sessions__


class Shellcode(Module):
    cmd = 'shellcode'
    description = 'Search for known shellcode patterns'
    authors = ['Kevin Breen', 'nex']

    def __init__(self):
        super(Shellcode, self).__init__()

    def run(self):

        super(Shellcode, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        collection = [
            {
                'description': 'FS:[30h] shellcode',
                'patterns': [
                    b'\x64\xa1\x30\x00|\x64\x8b\x0d\x30|\x64\x8b\x0d\x30|\x64\x8b\x15\x30|\x64\x8b\x35\x30|\x64\x8b\x3d\x30|\x6a\x30.\x64\x8b|\x33..\xb3\x64\x8b',
                    '64a13000|648b0d30|648b0d30|648b1530|648b3530|648b3d30|6a30..648b|33....b3648b'
                ]
            },
            {
                'description': 'FS:[00h] shellcode',
                'patterns': [
                    b'\x64\x8b\x1d|\x64\xa1\x00|\x64\x8b\x0d|\x64\x8b\x15|\x64\x8b\x35|\x64\x8b\x3d',
                    '648b1d00|64a10000|648b0d00|648b1500|648b3500|648b3d00'
                ]
            },
            {
                'description': 'API hashing',
                'patterns': [
                    b'\x74.\xc1.\x0d\x03|\x74.\xc1.\x07\x03',
                    '74..c1..0d03|74..c1..0703'
                ]
            },
            {
                'description': 'PUSH DWORD[]/CALL[]',
                'patterns': [
                    b'\x00\xff\x75\x00\xff\x55',
                    '00ff7500ff55'
                ]
            },
            {
                'description': 'FLDZ/FSTENV [esp-12]',
                'patterns': [
                    b'\x00\xd9\x00\xee\x00\xd9\x74\x24\x00\xf4\x00\x00',
                    '00d900ee00d9742400f40000'
                ]
            },
            {
                'description': 'CALL next/POP',
                'patterns': [
                    b'\x00\xe8\x00\x00\x00\x00(\x58|\x59|\x5a|\x5b|\x5e|\x5f|\x5d)\x00\x00',
                    '00e800000000(58|59|5a|5b|5e|5f|5d)0000'
                ]
            },
            {
                'description': 'Function prolog',
                'patterns': [
                    b'\x55\x8b\x00\xec\x83\x00\xc4|\x55\x8b\x0ec\x81\x00\xec|\x55\x8b\x00\xec\x8b|\x55\x8b\x00\xec\xe8|\x55\x8b\x00\xec\xe9',
                    '558b00ec8300c4|558b0ec8100ec|558b00ec8b|558b00ece8|558b00ece9'
                ]
            },

        ]

        self.log('info', "Searching for known shellcode patterns...")

        for entry in collection:
            for pattern in entry['patterns']:
                match = re.search(pattern, __sessions__.current.file.data)
                if match:
                    offset = match.start()
                    self.log('info', "{0} pattern matched at offset {1}".format(entry['description'], offset))
                    self.log('', cyan(hexdump(__sessions__.current.file.data[offset:], maxlines=15)))
