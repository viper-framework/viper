# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

class XorSearch(Module):
    cmd = 'xor'
    description = 'Search for xor Strings'
    authors = ['Kevin Breen', 'nex']

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
            'VirtualAlloc'
        ]

        def usage():
            print("usage: xor [-s=term]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--search (-s)\tSpecify a custom term to search")
            print("")

        def xordata(data, key):
            encoded = bytearray(data)
            for i in range(len(encoded)):
                encoded[i] ^= key

            return encoded

        try:
            opts, argv = getopt.getopt(self.args, 'hs:', ['help', 'search='])
        except getopt.GetoptError as e:
            print(e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--search'):
                terms = [value]

        if not __session__.is_set():
            print_error("No session opened")
            return

        print_info("Searching for the following XORed strings:")
        for term in terms:
            print_item(term)

        print_info("Hold on, this might take a while...")
        for key in range(256):
            if key == 0 :
                continue

            xored = xordata(__session__.file.data, key)
            for term in terms:
                if term in xored:
                    print_error("Matched: {0} with key: {1}".format(term, hex(key)))
