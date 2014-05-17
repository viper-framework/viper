# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os

class Project(object):
    def __init__(self):
        self.name = None
        self.path = None

    def open(self, name):
        path = os.path.join(os.getcwd(), 'projects', name)
        if not os.path.exists(path):
            os.makedirs(path)

        self.name = name
        self.path = path

    def get_path(self):
        if self.path and os.path.exists(self.path):
            return self.path
        else:
            return os.getcwd()

__project__ = Project()
