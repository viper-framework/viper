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
            self.log('', "usage: xor [-x] [-r] [-a] [-o] [-s=term]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--search (-s)\tSpecify a custom term to search")
            self.log('', "\t--xor (-x)\tSearch XOR (default)")
            self.log('', "\t--rot (-r)\tSearch ROT")
            self.log('', "\t--all (-a)\tAttempt search with all available modes")
            self.log('', "\t--output (-o)\tSave Decoded Data")
            self.log('', "")

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

                    
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return
            
        try:
            opts, argv = getopt.getopt(self.args, 'hxrao:s:', ['help', 'xor', 'rot', 'all',  'output=', 'search='])
        except getopt.GetoptError as e:
            self.log('', e)
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
