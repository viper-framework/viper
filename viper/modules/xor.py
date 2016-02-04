# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

# TODO
# ROL, ROR

import os

from viper.common.abstracts import Module
from viper.core.session import __sessions__


class XorSearch(Module):
    cmd = 'xor'
    description = 'Search for xor Strings'
    authors = ['Kevin Breen', 'nex']

    def __init__(self):
        super(XorSearch, self).__init__()
        self.parser.add_argument('-s', '--search', metavar='terms', nargs='+', help='Specify a custom term to search')
        self.parser.add_argument('-x', '--xor', action='store_true', help='Search XOR (default)')
        self.parser.add_argument('-r', '--rot', action='store_true', help='Search ROT')
        self.parser.add_argument('-a', '--all', action='store_true', help='Attempt search with all available modes')
        self.parser.add_argument('-o', '--output', metavar='path', help='Save Decoded Data')

    def run(self):
        terms = [
            'This Program',
            'GetSystemDirectory',
            'CreateFile',
            'IsBadReadPtr',
            'IsBadWritePtr'
            'GetProcAddress',
            'LoadLibrary',
            'WinExec',
            'CreateFile'
            'ShellExecute',
            'CloseHandle',
            'UrlDownloadToFile',
            'GetTempPath',
            'ReadFile',
            'WriteFile',
            'SetFilePointer',
            'GetProcAddr',
            'VirtualAlloc',
            'http'
        ]

        def xordata(data, key):
            encoded = bytearray(data)
            for i in range(len(encoded)):
                encoded[i] ^= key
            return encoded

        def rotdata(data, key):
            encoded = ''
            for char in data:
                if char.isalpha():
                    num = ord(char)
                    num -= key
                    if num == ord('z') or num == ord('Z'):
                        num += 26
                    elif num == ord('a') or num == ord('A'):
                        num -= 26
                    encoded += chr(num)
            return encoded.lower()

        def xor_search(terms, save_path):
            for key in range(1, 256):
                found = False
                xored = xordata(__sessions__.current.file.data, key)
                for term in terms:
                    if term in xored:
                        found = True
                        self.log('error', "Matched: {0} with key: {1}".format(term, hex(key)))
                if found and save_path:
                    save_output(xored, save_path, key)

        def rot_search(terms, save_path):
            for key in range(1, 25):
                found = False
                roted = rotdata(__sessions__.current.file.data, key)
                for term in terms:
                    if term.lower() in roted:
                        found = True
                        self.log('error', "Matched: {0} with ROT: {1}".format(term, key))
                if found and save_path:
                    save_output(roted, save_path, key)

        def save_output(data, save_path, key):
            # Path Validation
            if not os.path.exists(save_path):
                try:
                    os.makedirs(save_path)
                except Exception as e:
                    self.log('error', "Unable to create directory at {0}: {1}".format(save_path, e))
                    return
            else:
                if not os.path.isdir(save_path):
                    self.log('error', "You need to specify a folder not a file")
                    return
            save_name = "{0}/{1}_{2}.bin".format(save_path, __sessions__.current.file.name, str(hex(key)))
            with open(save_name, 'wb') as output:
                output.write(data)
            self.log('info', "Saved Output to {0}".format(save_name))

        super(XorSearch, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        xor = self.args.xor
        rot = self.args.rot
        save_path = self.args.output

        if not xor and not rot:
            xor = True
        if self.args.search is not None:
            terms = self.args.search
        if self.args.all:
            xor = True
            rot = True

        self.log('info', "Searching for the following strings:")
        for term in terms:
            self.log('item', term)

        self.log('info', "Hold on, this might take a while...")

        if xor:
            self.log('info', "Searching XOR")
            xor_search(terms, save_path)

        if rot:
            self.log('info', "Searching ROT")
            rot_search(terms, save_path)
