#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys


if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "viper.web.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
