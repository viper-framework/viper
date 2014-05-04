# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

class xorSearch(Module):
    cmd = 'xor'
    description = 'Search for xor Strings'

    def run(self):
        terms = ['This Program',
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
                'VirtualAlloc']

        def usage():
            print("usage: xor -s [String]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--search (-s)\tSearch Term")

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
            elif opt in ('-s', '--session'):
                terms = [value]

        # Search for known bad strings with a one byte xor
        print_info("Searching For Known Strings, Please be Patient")
        data = open(__session__.file.path, 'rb').read()
        for key in range(256):
            newdata = xordata(data, key)
            for term in terms:
                if term in newdata:
                    print_error("Matched: {0} With Key: {1}".format(term, hex(key)))
