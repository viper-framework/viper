# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.
import os

from viper.common.out import *
from viper.common.utils import *
from viper.core.plugins import __modules__
from viper.core.session import __sessions__
from viper.core.database import Database
from viper.core.config import Config
from viper.core.storage import get_sample_path

cfg = Config()

# Read a list of command lines from the config file and execute them each time a sample is STORED.
def parse(data):
    root = ''
    args = []
    words = data.split()
    root = words[0]

    if len(words) > 1:
        args = words[1:]

    return (root, args)

def autorun_module(file_hash):
    if not file_hash:
        return

    # We need an open session
    if not __sessions__.is_set():
        # Open session
        __sessions__.new(get_sample_path(file_hash))

    for cmd_line in cfg.autorun.commands.split(','):
        split_commands = cmd_line.split(';')

        for split_command in split_commands:
            split_command = split_command.strip()

            if not split_command:
                continue

            root, args = parse(split_command)

            try:
                if root in __modules__:
                    print_info("Running command \"{0}\"".format(split_command))

                    module = __modules__[root]['obj']()
                    module.set_commandline(args)
                    module.run()
                    
                    if cfg.modules.store_output and __sessions__.is_set():
                        Database().add_analysis(file_hash, split_command, module.output)
                    
                    if cfg.autorun.verbose:
                        print_output(module.output)

                    del(module.output[:])
                else:
                    print_error("\"{0}\" is not a valid command. Please check your viper.conf file.".format(cmd_line))
            except:
                print_error("Viper was unable to complete the command {0}".format(cmd_line))
