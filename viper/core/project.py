# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

from viper.core.config import Config

cfg = Config()

class Project(object):
    def __init__(self):
        self.name = None
        self.path = None
        if cfg.paths.storage_path:
            self.path = cfg.paths.storage_path
        else:
            self.path = os.path.join(os.getenv('HOME'), '.viper')

        if not os.path.exists(self.path):
            os.makedirs(self.path)
        
    def open(self, name):
        if cfg.paths.storage_path:
            base_path = cfg.paths.storage_path
        else:
            base_path = os.path.join(os.getenv('HOME'), '.viper')

        if not os.path.exists(base_path):
            raise Exception("The local storage folder does not exist at path {}".format(
                base_path))

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
