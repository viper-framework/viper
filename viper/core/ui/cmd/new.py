# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import tempfile

from viper.common.abstracts import Command
from viper.common.colors import bold
from viper.core.session import __sessions__


class New(Command):
    """
    This command is used to create a new session on a new file,
    useful for copy & paste of content like Email headers.
    """
    cmd = "new"
    description = "Create new file"

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        title = input("Enter a title for the new file: ")

        # Create a new temporary file.
        tmp = tempfile.NamedTemporaryFile(delete=False)

        # Open the temporary file with the default editor, or with nano.
        os.system('"${EDITOR:-nano}" ' + tmp.name)

        __sessions__.new(tmp.name)
        __sessions__.current.file.name = title

        self.log('info', "New file with title \"{0}\" added to the current session".format(bold(title)))
