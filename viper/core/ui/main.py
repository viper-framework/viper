#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import argparse

from viper.core.ui import console
from viper.common.version import __version__
from viper.core.project import __project__
from viper.core.session import __sessions__

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p",
        "--project",
        help="Specify a new or existing project name",
        action="store",
        required=False)
    parser.add_argument(
        "-f",
        "--file",
        help="Specify a file to be opened directly",
        action="store",
        required=False)
    parser.add_argument(
        "--version",
        action="version",
        version=__version__)

    args = parser.parse_args()

    if args.project:
        __project__.open(args.project)

    if args.file:
        if not os.path.exists(args.file):
            print("ERROR: The specified path does not exist")
            sys.exit(-1)

        __sessions__.new(args.file)

    c = console.Console()
    c.start()
