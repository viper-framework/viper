# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

from viper.common.out import *
from viper.common.objects import File
from viper.core.database import Database

class Session(object):
    def __init__(self):
        # This will be assigned with the File object of the file currently
        # being analyzed.
        self.file = None
        # This is not being used yet.
        self.plugin = None
        # Store the results of the last "find" command.
        self.find = None

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

        # Try to lookup the file in the database. If it is already present
        # we get file name and 
        row = Database().find(key='sha256', value=__session__.file.sha256)
        if row:
            self.file.name = row[0].name
            self.file.tags = ', '.join(tag.to_dict()['tag'] for tag in row[0].tag)

        print_info("Session opened on {0}".format(path))

__session__ = Session()
