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

    def open_radare(self):
        command_line = 'r2 {}'.format(__sessions__.current.file.path)
        try:
            os.system(command_line)
        except Exception:
            self.log('error', "Unable to start Radare2")

    def command(self, command):
        r = r2pipe.open(__sessions__.current.file.path)
        self.log('info', r.cmd(command))

    def run(self):
        super(Radare, self).run()
        if self.args is None:
            return

        r2command = ' '.join(self.args.command)
        if not __sessions__.is_set():
            if os.path.isfile(r2command):
                __sessions__.new(r2command)
                self.open_radare()
                return
            else:
                self.log('error', "No open session")
                return

        if not r2command:
            self.open_radare()
        else:
            self.command(r2command)
