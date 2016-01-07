#!/usr/bin/env python
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import argparse

from viper.core.ui import console
from viper.core.project import __project__

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--repository', help='Specify a new or existing repository', action='store', required=False)
parser.add_argument('-p', '--project', help='Specify a new or existing project name', action='store', required=False)
args = parser.parse_args()

repository_root = None
if args.repository:
	repository_root = args.repository

project_name = None
if args.project:
	project_name = args.project

c = console.Console(repository_root)
c.start(project_name)
