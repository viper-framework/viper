# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

# TODO
# ROL, ROR

import os
import getopt
from string import ascii_lowercase as lc, ascii_uppercase as uc

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

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
            'VirtualAlloc',
            'http'
        ]

        def usage():
            print("usage: xor [-x -r -s=term]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--search (-s)\tSpecify a custom term to search")
            print("\t--xor (-x)\t Search XOR (Default)")
            print("\t--rot (-r)\t Search ROT")
            print("")

        def xordata(data, key):
            encoded = bytearray(data)
            for i in range(len(encoded)):
                encoded[i] ^= key
            return encoded

        def rotdata(data, key):
            coded = ''
            for char in data:
                if char.isalpha():
                    num = ord(char)
                    num -= key
                    if num == ord('z') or num == ord('Z'):
                        num += 26
                    elif num == ord('a') or num == ord('A'):
                        num -= 26
                    coded += chr(num)
            return coded.lower()
        
        def xor_search(terms):
            for key in range(1, 256):
                xored = xordata(__sessions__.current.file.data, key)
                for term in terms:
                    if term in xored:
                        print_error("Matched: {0} with key: {1}".format(term, hex(key)))
   
        def rot_search(terms):
            for key in range(1, 25):
                roted = rotdata(__sessions__.current.file.data, key)
                for term in terms:
                    if term.lower() in roted:
                        print_error("Matched: {0} with ROT: {1}".format(term, key))
                        
        # Main starts here
        # Check for open session
        if not __sessions__.is_set():
            print_error("No session opened")
            return
            
        # get opt and args
        try:
            opts, argv = getopt.getopt(self.args, 'hxras:', ['help', 'xor', 'rot', 'all',  'search='])
        except getopt.GetoptError as e:
            print(e)
            return

        xor = True
        rot = False
        
        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--search'):
                terms = [value]   
            elif opt in ('-x', '--xor'):
                xor = True
            elif opt in ('-r', '--rot'):
                rot = True
                xor = False
            elif opt in ('-a', '--all'):
                xor = True
                rot = True

        print_info("Searching for the following strings:")
        for term in terms:
            print_item(term)

        print_info("Hold on, this might take a while...")

        if xor:
            print_info("Searching XOR")
            xor_search(terms)
        if rot:
            print_info("Searching ROT")
            rot_search(terms)
        
