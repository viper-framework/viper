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
            print("usage: xor [-x] [-r] [-a] [-o] [-s=term]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--search (-s)\tSpecify a custom term to search")
            print("\t--xor (-x)\tSearch XOR (default)")
            print("\t--rot (-r)\tSearch ROT")
            print("\t--all (-a)\tAttempt search with all available modes")
            print("\t--output (-o)\tSave Decoded Data")
            print("")

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
                        print_error("Matched: {0} with key: {1}".format(term, hex(key)))
                if found and save_path:
                    save_output(xored, save_path, key)
   
        def rot_search(terms, save_path):
            for key in range(1, 25):
                found = False
                roted = rotdata(__sessions__.current.file.data, key)
                for term in terms:
                    if term.lower() in roted:
                        found = True
                        print_error("Matched: {0} with ROT: {1}".format(term, key))
                if found and save_path:
                    save_output(roted, save_path, key)

        def save_output(data, save_path, key):
            # Path Validation
            if not os.path.exists(save_path):
                try:
                    os.makedirs(save_path)
                except Exception as e:
                    print_error("Unable to create directory at {0}: {1}".format(save_path, e))
                    return
            else:
                if not os.path.isdir(save_path):
                    print_error("You need to specify a folder not a file")
                    return           
            save_name = "{0}/{1}_{2}.bin".format(save_path, __sessions__.current.file.name, str(hex(key)))
            with open(save_name, 'wb') as output:
                output.write(data)
            print_info("Saved Output to {0}".format(save_name))

                    
        if not __sessions__.is_set():
            print_error("No session opened")
            return
            
        try:
            opts, argv = getopt.getopt(self.args, 'hxrao:s:', ['help', 'xor', 'rot', 'all',  'output=', 'search='])
        except getopt.GetoptError as e:
            print(e)
            return

        xor = True
        rot = False
        save_path = False
        
        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            if opt in ('-o', '--output'):
                save_path = value
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
            xor_search(terms, save_path)

        if rot:
            print_info("Searching ROT")
            rot_search(terms, save_path)
