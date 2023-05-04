# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.out import print_error, print_info, print_output
from viper.core.config import cfg
from viper.core.database import Database
from viper.core.plugins import modules
from viper.core.sessions import sessions
from viper.core.storage import get_sample_path


def parse_commands(data):
    root = ""
    args = []
    words = data.split()
    root = words[0]

    if len(words) > 1:
        args = words[1:]

    return root, args


def autorun_module(file_hash: str):
    if not file_hash:
        return

    if not sessions.is_set():
        sessions.new(get_sample_path(file_hash))

    for cmd_line in cfg.autorun.commands.split(","):
        split_commands = cmd_line.split(";")

        for split_command in split_commands:
            split_command = split_command.strip()

            if not split_command:
                continue

            root, args = parse_commands(split_command)

            try:
                if root in modules:
                    print_info(f'Running command "{split_command}"')

                    module = modules[root]["obj"]()
                    module.set_commandline(args)
                    module.run()

                    if cfg.modules.store_output and sessions.is_set():
                        Database().add_analysis(file_hash, split_command, module.output)

                    if cfg.autorun.verbose:
                        print_output(module.output)

                    del module.output[:]
                else:
                    print_error(
                        f'"{cmd_line}" is not a valid command: please check your viper.conf file'
                    )
            except Exception:
                print_error(f'Viper was unable to complete the command "{cmd_line}"')
