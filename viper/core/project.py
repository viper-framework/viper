# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import time

from viper.core.config import Config
cfg = Config()

class Project(object):
    def __init__(self):
        self.name = None
        self.path = None

        if cfg.paths.store_path:
            self.path = cfg.paths.store_path
        else:
            self.path = os.getcwd()

        if not os.path.exists(self.path):
            os.makedirs(self.path)
        
    def open(self, name):
        if name == 'default':
            path = self.path
        else:
            path = os.path.join(self.path, 'projects', name)
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