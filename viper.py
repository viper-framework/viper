#!/usr/bin/env python
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import argparse

from viper.core.ui import console
from viper.core.project import __project__

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--project', help='Specify a new or existing project name', action='store', required=False)
args = parser.parse_args()

if args.project:
    __project__.open(args.project)

config_paths = [
	os.path.join(os.getcwd(), 'viper.conf'),
	os.path.join(os.getenv('HOME'), '.viper', 'viper.conf'),
	'/etc/viper/viper.conf'
]

config_file = None
for config_path in config_paths:
	if os.path.exists(config_path):
		config_file = config_path
		break

if not config_file:
	print("Unable to find any config file!")
else:
	c = console.Console()
	c.start()
