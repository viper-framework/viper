# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
VIPER_ROOT = os.path.normpath(os.path.join(_current_dir, "..", ".."))

DIST_DIR_YARA_RULES = "viper_data_yara"
DIST_DIR_PEID = "viper_data_peid"
