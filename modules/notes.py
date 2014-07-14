# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class Notes(Module):
    cmd = 'notes'
    description = 'Write notes about currently open file'
    authors = ['Sascha Rommelfangen']

    def OpenNotepad(self, filename):
        destination = filename + ".txt"
        command = "edit " + destination
        os.system(command)
   
    def run(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return
        try:
            filename = __sessions__.current.file.path
            self.OpenNotepad(filename)

        except OSError:
            print_error("Editor is not installed")
            return

