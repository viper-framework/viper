# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import shlex
import subprocess

from viper.common.abstracts import Module
from viper.core.session import __sessions__

ext = ".bin"

run_ida = {'linux2': 'idaq', 'darwin': 'open -a idaq',
           'win32': 'idaq'}


class Ida(Module):
    cmd = 'ida'
    description = 'Start IDA Pro'
    authors = ['Sascha Rommelfangen', 'Raphaël Vinot']

    def __init__(self):
        super(Ida, self).__init__()
        self.is_64b = False
        self.ext = ''

    def open_ida(self, filename):
        directory = filename + ".dir"

        if not os.path.exists(directory):
            os.makedirs(directory)

        destination = directory + "/executable" + self.ext

        if not os.path.lexists(destination):
            os.link(filename, destination)

        if self.is_64b:
            command_line = '{}64 {}'.format(run_ida[sys.platform], destination)
        else:
            command_line = '{} {}'.format(run_ida[sys.platform], destination)

        args = shlex.split(command_line)
        subprocess.Popen(args)

    def run(self):
        super(Ida, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        filetype = __sessions__.current.file.type
        if 'x86-64' in filetype:
            self.is_64b = True
        if 'DLL' in filetype:
            self.ext = '.dll'
        elif 'PE32' in filetype:
            self.ext = '.exe'
        elif 'shared object' in filetype:
            self.ext = '.so'
        elif 'ELF' in filetype:
            self.ext = ''
        else:
            self.log('error', "File type not supported")
            return

        arch = '64' if self.is_64b else '32'

        if self.ext == '':
            self.log('info', ' '.join([arch, 'bit executable (linux)']))
        elif self.ext == '.so':
            self.log('info', ' '.join([arch, 'bit shared object (linux)']))
        elif self.ext == '.exe':
            self.log('info', ' '.join([arch, 'bit executable (Windows)']))
        else:
            to_print = [arch, 'bit DLL (Windows)']
            if "native" in filetype:
                to_print.append('perhaps a driver (.sys)')

            self.log('info', ' '.join(to_print))

        try:
            self.open_ida(__sessions__.current.file.path)
        except Exception:
            self.log('error', "Unable to start IDA Pro")
