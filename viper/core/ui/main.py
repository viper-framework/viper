# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
import os
import sys

from viper.common.version import VIPER_VERSION
from viper.core.projects import project
from viper.core.sessions import sessions
from viper.core.ui import console


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p",
        "--project",
        help="Specify a new or existing project name",
        action="store",
        required=False,
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Specify a file to be open directly",
        action="store",
        required=False,
    )
    parser.add_argument("--version", action="version", version=VIPER_VERSION)

    args = parser.parse_args()

    if args.project:
        project.open(args.project)

    if args.file:
        if not os.path.exists(args.file):
            print("ERROR: The specified path does not exist")
            sys.exit(-1)

        sessions.new(args.file)

    c = console.Console()
    c.start()
