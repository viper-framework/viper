# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import atexit
import glob
import logging
import os
import readline
import sys
import traceback
from os.path import expanduser

from rich.console import Console as RichConsole

# from viper.common.out import print_output  # currently not used
from viper.common.out import print_error
from viper.common.version import VIPER_VERSION
from viper.core.config import cfg, console_output
from viper.core.database import Database
from viper.core.plugins import modules
from viper.core.projects import get_project_list, project
from viper.core.sessions import sessions
from viper.core.ui.commands import Commands

log = logging.getLogger("viper")

cfg.parse_http_client()


def logo():
    print(
        f"""
  ██    ██ ██ ██████  ███████ ██████  
  ██    ██ ██ ██   ██ ██      ██   ██ 
  ██    ██ ██ ██████  █████   ██████  
   ██  ██  ██ ██      ██      ██   ██ 
    ████   ██ ██      ███████ ██   ██  v{VIPER_VERSION}
"""
    )

    db = Database()
    count = db.get_sample_count()

    try:
        db.find("all")
    except Exception:
        sys.exit()

    if project.name:
        name = project.name
    else:
        name = "default"

    console = RichConsole()
    console.print(
        f"[magenta]You have [bold]{count}[/bold] files in your [bold]{name}[/bold] repository"
    )

    modules_count = len(modules)
    if modules_count == 0:
        print("")
        console.print("[bold red]You do not have any modules installed![/bold red]")
        console.print(
            "[red]If you wish to download community modules from GitHub run:[/red]"
        )
        console.print("[bold red]    update-modules[/bold red]")
    else:
        console.print(
            f"[magenta]You have [bold]{modules_count}[/bold] modules installed"
        )


class Console:
    def __init__(self):
        # This will keep the main loop active as long as it's set to True.
        self.active = True
        self.cmd = Commands()

    @staticmethod
    def parse(data):
        root = ""
        args = []

        # Split words by white space.
        words = data.split()
        # First word is the root command.
        root = words[0]

        # If there are more words, populate the arguments list.
        if len(words) > 1:
            args = words[1:]

        return (root, args)

    @staticmethod
    def keywords(data):
        # Check if $self is in the user input data.
        if "$self" in data:
            # Check if there is an open session.
            if sessions.is_set():
                # If a session is open, replace $self with the path to
                # the file which is currently being analyzed.
                data = data.replace("$self", sessions.current.file.path)
            else:
                print("No open session")
                return None

        return data

    @staticmethod
    def complete(text, state):
        # filesystem path completion only makes sense for a few commands/modules
        fs_path_completion = False

        # clean up user input so far (no leading/trailing/duplicate spaces)
        line = " ".join(readline.get_line_buffer().split())
        words = line.split(
            " "
        )  # split words; e.g. store -f /tmp -> ["store", "-f", "/tmp"]

        if words[0] in [i for i in self.cmd.commands]:
            # handle completion for commands

            # enable filesystem path completion for certain commands (e.g. export, store)
            if words[0] in [
                x
                for x in self.cmd.commands
                if self.cmd.commands[x]["fs_path_completion"]
            ]:
                fs_path_completion = True

            options = [key for key in self.cmd.commands[words[0]]["parser_args"]]

            # enable tab completion for projects --switch
            if words[0] == "projects":
                if "--switch" in words or "-s" in words:
                    options += get_project_list()

                    # enable tab completion for copy (list projects)
            if words[0] == "copy":
                options += get_project_list()

            completions = [
                i for i in options if i.startswith(text) and i not in words
            ]

        elif words[0] in [i for i in modules]:
            # handle completion for modules
            if len(words) == 1:
                # only the module name is give so far - present all args and the subparsers (if any)
                options = [key for key in modules[words[0]]["parser_args"]]
                options += [key for key in modules[words[0]]["subparser_args"]]

            elif len(words) == 2:
                # 1 complete word and one either complete or incomplete that specifies the subparser or an arg
                if words[1] in list(modules[words[0]]["parser_args"]):
                    # full arg for a module is given
                    options = [key for key in modules[words[0]]["parser_args"]]

                elif words[1] in list(modules[words[0]]["subparser_args"]):
                    # subparser is specified - get all subparser args
                    options = [
                        key for key in modules[words[0]]["subparser_args"][words[1]]
                    ]

                else:
                    options = [key for key in modules[words[0]]["parser_args"]]
                    options += [key for key in modules[words[0]]["subparser_args"]]

            else:  # more that 2 words
                if words[1] in list(modules[words[0]]["subparser_args"]):
                    # subparser is specified - get all subparser args
                    options = [
                        key for key in modules[words[0]]["subparser_args"][words[1]]
                    ]
                else:
                    options = [key for key in modules[words[0]]["parser_args"]]

            completions = [
                i for i in options if i.startswith(text) and i not in words
            ]

        else:
            # initial completion for both commands and modules
            completions = [i for i in self.cmd.commands if i.startswith(text)]
            completions += [i for i in modules if i.startswith(text)]

        if state < len(completions):
            return completions[state]

        if fs_path_completion:
            # completion for paths only if it makes sense
            if text.startswith("~"):
                text = "{0}{1}".format(expanduser("~"), text[1:])
            return (glob.glob(text + "*") + [None])[state]

        return

    @staticmethod
    def save_history(path):
        readline.write_history_file(path)

    def stop(self):
        # Stop main loop.
        self.active = False

    def start(self):
        # log start
        log.info("Starting viper")

        # Logo.
        logo()

        # Auto-complete on tabs.
        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.complete)

        # If there is an history file, read from it and load the history
        # so that they can be loaded in the shell.
        # Now we are storing the history file in the local project folder
        history_path = os.path.join(project.path, "history")

        if os.path.exists(history_path):
            readline.read_history_file(history_path)

        readline.set_history_length(10000)

        # Register the save history at program's exit.
        atexit.register(self.save_history, path=history_path)

        # Main loop.
        while self.active:
            # If there is an open session, we include the path to the open
            # file in the shell prompt.
            # TODO: perhaps this block should be moved into the session so that
            # the generation of the prompt is done only when the session"s
            # status changes.
            prefix = ""
            if project.name:
                prefix = f"[bold cyan]{project.name}[/bold cyan] "

            if sessions.is_set():
                stored = ""
                filename = ""
                if sessions.current.file:
                    filename = sessions.current.file.name
                    if not Database().find(
                        key="sha256", value=sessions.current.file.sha256
                    ):
                        stored = " [magenta][not stored][/magenta]"

                prompt = f"{prefix}[cyan]viper [/cyan][white]{filename}[/white]{stored}[cyan]> [/cyan]"
            # Otherwise display the basic prompt.
            else:
                prompt = f"{prefix}[cyan]viper > [/cyan]"

            # Wait for input from the user.
            try:
                console = RichConsole()
                data = console.input(prompt).strip()
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
                    print("")
                    continue

                # Check for output redirection
                # If there is a > in the string, we assume the user wants to output to file.
                if ">" in data:
                    data, console_output["filename"] = data.split(">", 1)
                    if ";" in console_output["filename"]:
                        console_output["filename"], more_commands = console_output[
                            "filename"
                        ].split(";", 1)
                        data = "{};{}".format(data, more_commands)
                    print(
                        "Writing output to {0}".format(
                            console_output["filename"].strip()
                        )
                    )

                # If the input starts with an exclamation mark, we treat the
                # input as a bash command and execute it.
                # At this point the keywords should be replaced.
                if data.startswith("!"):
                    os.system(data[1:])
                    continue

                # Try to split commands by ; so that you can sequence multiple
                # commands at once.
                # For example:
                # viper > find name *.pdf; open --last 1; pdf id
                # This will automatically search for all PDF files, open the first entry
                # and run the pdf module against it.
                split_commands = data.split(";")
                for split_command in split_commands:
                    split_command = split_command.strip()
                    if not split_command:
                        continue

                    # If it's an internal command, we parse the input and split it
                    # between root command and arguments.
                    root, args = self.parse(split_command)

                    # Check if the command instructs to terminate.
                    if root in ("exit", "quit"):
                        self.stop()
                        continue

                    try:
                        # If the root command is part of the embedded commands list we
                        # execute it.
                        if root in self.cmd.commands:
                            self.cmd.commands[root]["obj"](*args)
                            del self.cmd.output[:]
                        # If the root command is part of loaded modules, we initialize
                        # the module and execute it.
                        elif root in modules:
                            module = modules[root]["obj"]()
                            module.set_commandline(args)
                            module.run()

                            if cfg.modules.store_output and sessions.is_set():
                                try:
                                    Database().add_analysis(
                                        sessions.current.file.sha256,
                                        split_command,
                                        module.output,
                                    )
                                except Exception:
                                    pass
                            del module.output[:]
                        else:
                            print("Command not recognized.")
                    except KeyboardInterrupt:
                        pass
                    except Exception:
                        print_error(f'The command "{root}" raised an exception')
                        traceback.print_exc()

                console_output["filename"] = None  # reset output to stdout
