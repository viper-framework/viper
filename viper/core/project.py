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

    def is_open(self):
        if self.path == None:
            return False

        return True
        
    def open(self, absolute_project_path):
        self.path = absolute_project_path
        self.name = os.path.basename(absolute_project_path).replace(" ", "_")

        if not os.path.exists(self.path):
            os.makedirs(self.path)

    def get_absolute_path(self):
        return self.path

    def get_name(self):
        return self.name

__project__ = Project()