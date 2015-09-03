# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

from viper.core.config import Config

class Project(object):
    def __init__(self):
        self.name = None
        self.path = None

        cfg = Config()
        if cfg.paths.root_path:
            self.root_path = cfg.paths.root_path
        else:
            self.root_path = os.getcwd()
            
        if not os.path.exists(self.root_path):
            os.makedirs(self.root_path)
        
    def open(self, name):

        path = os.path.join(self.root_path, 'projects', name)
        if not os.path.exists(path):
            os.makedirs(path)

        self.name = name
        self.path = path

    def get_path(self):
        if self.path and os.path.exists(self.path):
            return self.path
        else:
            return self.root_path

__project__ = Project()
