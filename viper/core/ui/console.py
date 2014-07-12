# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import glob
import atexit
import readline
import traceback

from viper.common.out import *
from viper.core.session import __sessions__
from viper.core.plugins import __modules__
from viper.core.project import __project__
from viper.core.ui.commands import Commands
from viper.core.storage import get_sample_path
from viper.core.database import Database

def logo():
    print("""         _                   
        (_) 
   _   _ _ ____  _____  ____ 
  | | | | |  _ \| ___ |/ ___)
   \ V /| | |_| | ____| |    
    \_/ |_|  __/|_____)_| v1.1-dev
          |_|
    """)

    db = Database()
    count = db.get_sample_count()

    if __project__.name:
        name = __project__.name
    else:
        name = 'default'

    print(magenta("You have " + bold(count)) + 
          magenta(" files in your " + bold(name) + 
          magenta(" repository".format(bold(name)))))

class Console(object):

    def __init__(self):
        # This will keep the main loop active as long as it's set to True.
        self.active = True
        self.cmd = Commands()

    def parse(self, data):
        root = ''
        args = []

        # Split words by white space.
        words = data.split()
        # First word is the root command.
        root = words[0]

        # If there are more words, populate the arguments list.
        if len(words) > 1:
            args = words[1:]

        return (root, args)

    def keywords(self, data):
        # Check if $self is in the user input data.
        if '$self' in data:
            # Check if there is an open session.
            if __sessions__.is_set():
                # If a session is opened, replace $self with the path to
                # the file which is currently being analyzed.
                data = data.replace('$self', __sessions__.current.file.path)
            else:
                print("No session opened")
                return None

        return data

    def stop(self):
        # Stop main loop.
        self.active = False

    def start(self):
        # Logo.
        logo()

        # Setup shell auto-complete.
        def complete(text, state):
            return (glob.glob(text+'*')+[None])[state]

        # Auto-complete on tabs.
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind('tab: complete')
        readline.set_completer(complete)

        # Save commands in history file.
        def save_history(path):
            readline.write_history_file(path)

        # If there is an history file, read from it and load the history
        # so that they can be loaded in the shell.
        # Now we are storing the history file in the local project folder
        # if there is an opened project. Otherwise just store it in the
        # home directory.
        if __project__.path:
            history_path = os.path.join(__project__.path, 'history')
        else:
            history_path = os.path.expanduser('~/.viperhistory')

        if os.path.exists(history_path):
            readline.read_history_file(history_path)

        # Register the save history at program's exit.
        atexit.register(save_history, path=history_path)

        # Main loop.
        while self.active:
            # If there is an open session, we include the path to the opened
            # file in the shell prompt.
            # TODO: perhaps this block should be moved into the session so that
            # the generation of the prompt is done only when the session's
            # status changes.
            prefix = ''
            if __project__.name:
                prefix = bold(cyan(__project__.name)) + ' '

            if __sessions__.is_set():
                prompt = prefix + cyan('shell ') + white(__sessions__.current.file.name) + cyan(' > ')
            # Otherwise display the basic prompt.
            else:
                prompt = prefix + cyan('shell > ')

            # Wait for input from the user.
            try:
                data = raw_input(prompt).strip()
            except KeyboardInterrupt:
                print("")
            # Terminate on EOF.
            except EOFError:
                self.stop()
                print("")
                continue
            # Parse the input if the user provided any.
            else:
                # If there are recognized keywords, we replace them with
                # their respective value.
                data = self.keywords(data)

                # Skip if the input is empty.
                if not data:
                    continue

                # If the input starts with an exclamation mark, we treat the
                # input as a bash command and execute it.
                # At this point the keywords should be replaced.
                if data.startswith('!'):
                    os.system(data[1:])
                    continue

                # If it's an internal command, we parse the input and split it
                # between root command and arguments.
                root, args = self.parse(data)

                # Check if the command instructs to terminate.
                if root in ('exit', 'quit'):
                    self.stop()
                    continue

                try:
                    # If the root command is part of the embedded commands list we
                    # execute it.
                    if root in self.cmd.commands:
                        self.cmd.commands[root]['obj'](*args)
                    # If the root command is part of loaded modules, we initialize
                    # the module and execute it.
                    elif root in __modules__:
                        module = __modules__[root]['obj']()
                        module.set_args(args)
                        module.run()
                    else:
                        print("Command not recognized.")
                except KeyboardInterrupt:
                    pass
                except Exception as e:
                    print_error("The command {0} raised an exception:".format(bold(root)))
                    traceback.print_exc()
