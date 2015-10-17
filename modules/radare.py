# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

from viper.common.abstracts import Module
from viper.core.session import __sessions__


class Radare(Module):
    cmd = 'r2'
    description = 'Start Radare2'
    authors = ['dukebarman', 'Raphaël Vinot']

    def __init__(self):
        super(Radare, self).__init__()
        self.parser.add_argument('-w', '--webserver', action='store_true', help='Start web-frontend for radare2')
        self.server = ''

    def open_radare(self, filename):
        command_line = 'r2 {} {}'.format(self.server, filename)
        os.system(command_line)

    def run(self):
        super(Radare, self).run()

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        if self.args.webserver:
            self.server = "-c=H"

        try:
            self.open_radare(__sessions__.current.file.path)
        except:
            self.log('error', "Unable to start Radare2")
