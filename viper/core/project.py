# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import time

from viper.common.constants import *
from viper.core.config import Config
cfg = Config()

class Project(object):
    def __init__(self):
        self.name = None
        self.path = None
        print "ini"
        if cfg.paths.store_path:
            self.path = cfg.paths.store_path
        else:
            self.path = VIPER_ROOT

        if not os.path.exists(self.path):
            os.makedirs(self.path)
        
    def open(self, name):
        if cfg.paths.store_path:
            base_path = cfg.paths.store_path
        else:
            base_path = VIPER_ROOT

        if name == 'default':
            path = base_path
        else:
            path = os.path.join(base_path, 'projects', name)
            if not os.path.exists(path):
                os.makedirs(path)
        self.name = name
        self.path = path

    def get_path(self):
        if self.path and os.path.exists(self.path):
            return self.path
        else:
            return self.path

__project__ = Project()