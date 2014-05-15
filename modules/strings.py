# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import re

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class Strings(Module):
    cmd = 'strings'
    description = 'Extract strings from file'
    authors = ['nex']

    def run(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if os.path.exists(__sessions__.current.file.path):
            try:
                data = open(__sessions__.current.file.path, 'r').read()
            except (IOError, OSError) as e:
                print_error("Cannot open file: {0}".format(e))

            strings = re.findall('[\x1f-\x7e]{6,}', data)

            for s in strings:
                print(s)
