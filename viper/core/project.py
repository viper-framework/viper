# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os

from config import project_path
from config import bin_path

class Project(object):
    def __init__(self):
        self.name = None
        self.path = None

    def open(self, name):
        if not project_path:
            path = os.path.join(os.getcwd(), 'projects', name)
        else:
            path = os.path.join(project_path, name)
        if not os.path.exists(path):
            os.makedirs(path)

        self.name = name
        self.path = path

    def get_path(self):
        if self.path and os.path.exists(self.path):
            return self.path
        if bin_path:
            if not os.path.exists(bin_path):
                os.makedirs(bin_path)
            return bin_path
        else:
            return os.getcwd()

__project__ = Project()
