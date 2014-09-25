# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import getopt

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

ext = ".bin"

run_radare = {'linux2': 'r2', 'darwin': 'r2',
           'win32': 'r2'}

class Radare(Module):
    cmd = 'r2'
    description = 'Start Radare2'
    authors = ['dukebarman']

    def __init__(self):
        self.is_64b = False
        self.ext = ''
        self.server = ''

    def open_radare(self, filename):
        directory = filename + ".dir"

        if not os.path.exists(directory):
            os.makedirs(directory)

        destination = directory + "/executable" + self.ext

        if not os.path.lexists(destination):
            os.link(filename, destination)

        command_line = '{} {}{}'.format(run_radare[sys.platform], self.server, destination)
        os.system(command_line)

    def run(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        def usage():
            print("usage: r2 [-h] [-s]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--webserver (-w)\tStart web-frontend for radare2")
            print("")

        try:
            opts, argv = getopt.getopt(self.args[0:], 'hw', ['help', 'webserver'])
        except getopt.GetoptError as e:
            print(e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-w', '--webserver'):
                self.server = "-c=H "

        filetype = __sessions__.current.file.type
        if 'x86-64' in filetype:
            self.is_64b = True

        arch = '64' if self.is_64b else '32'
        if 'DLL' in filetype:
            self.ext = '.dll'
            to_print = [arch, 'bit DLL (Windows)']
            if "native" in filetype:
                to_print.append('perhaps a driver (.sys)')

            print_info(' '.join(to_print))
        elif 'PE32' in filetype:
            self.ext = '.exe'
            print_info(' '.join([arch, 'bit executable (Windows)']))
        elif 'shared object' in filetype:
            self.ext = '.so'
            print_info(' '.join([arch, 'bit shared object (linux)']))
        elif 'ELF' in filetype:
            self.ext = ''
            print_info(' '.join([arch, 'bit executable (linux)']))
        else:
            print_error("Unknown binary")

        try:
            self.open_radare(__sessions__.current.file.path)
        except:
            print_error("Unable to start Radare2")
