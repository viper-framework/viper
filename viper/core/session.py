from viper.common.out import *
from viper.common.objects import File

class Session(object):
    def __init__(self):
        # This will be assigned with the File object of the file currently
        # being analyzed.
        self.file = None
        # This is not being used yet.
        self.plugin = None

    def clear(self):
        # Reset session attributes.
        self.plugin = None
        self.file = None

    def is_set(self):
        # Check if the session has been opened or not.
        if self.file:
            return True
        else:
            return False

    def set(self, path):
        # Open a section on the given file.
        self.file = File(path)
        print_info("Session opened on {0}".format(path))

__session__ = Session()
