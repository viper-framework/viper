import os
import re

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

class Strings(Module):
    cmd = 'strings'
    description = 'Extract strings from file'

    def run(self):
        if not __session__.is_set():
            print_error("No session opened")
            return

        if os.path.exists(__session__.file.path):
            try:
                data = open(__session__.file.path, 'r').read()
            except (IOError, OSError) as e:
                print_error("Cannot open file: {0}".format(e))

            strings = re.findall('[\x1f-\x7e]{6,}', data)

            for s in strings:
                print(s)
