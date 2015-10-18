# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import r2pipe

from viper.common.abstracts import Module
from viper.core.session import __sessions__


class Radare(Module):
    cmd = 'r2'
    description = 'Start Radare2'
    authors = ['dukebarman', 'Raphaël Vinot']

    def __init__(self):
        super(Radare, self).__init__()
        self.parser.add_argument('command', nargs='*', help='Run a radare2 command on the current file')
        self.server = ''

    def open_radare(self):
        command_line = 'r2 {} {}'.format(self.server, __sessions__.current.file.path)
        os.system(command_line)

    def command(self, command):
        r = r2pipe.open(__sessions__.current.file.path)
        print(r.cmd(command))

    def run(self):
        super(Radare, self).run()

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        r2command = ' '.join(self.args.command)
        if not r2command:
            try:
                self.open_radare()
            except:
                self.log('error', "Unable to start Radare2")
        else:
            self.command(r2command)
