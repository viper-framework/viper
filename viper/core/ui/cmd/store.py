# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import fnmatch
try:
    from scandir import walk
except ImportError:
    from os import walk

from viper.core.ui.cmd.open import Open
from viper.common.abstracts import Command
from viper.common.objects import File
from viper.core.database import Database
from viper.core.session import __sessions__
from viper.core.config import __config__
from viper.core.storage import store_sample, get_sample_path
from viper.common.autorun import autorun_module


class Store(Command):
    """
    This command stores the opened file in the local repository and tries
    to store details in the database.
    """
    cmd = "store"
    description = "Store the opened file to the local repository"
    fs_path_completion = True

    def __init__(self):
        super(Store, self).__init__()

        self.parser.add_argument('-d', '--delete', action='store_true', help="Delete the original file")
        self.parser.add_argument('-f', '--folder', type=str, nargs='+', help="Specify a folder to import")
        self.parser.add_argument('-s', '--file-size', type=int, help="Specify a maximum file size")
        self.parser.add_argument('-y', '--file-type', type=str, help="Specify a file type pattern")
        self.parser.add_argument('-n', '--file-name', type=str, help="Specify a file name pattern")
        self.parser.add_argument('-t', '--tags', type=str, nargs='+', help="Specify a list of comma-separated tags")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if args.folder is not None:
            # Allows to have spaces in the path.
            args.folder = " ".join(args.folder)

        if args.tags is not None:
            # Remove the spaces in the list of tags
            args.tags = "".join(args.tags)

        def add_file(obj, tags=None):
            if get_sample_path(obj.sha256):
                self.log('warning', "Skip, file \"{0}\" appears to be already stored".format(obj.name))
                return False

            if __sessions__.is_attached_misp(quiet=True):
                if tags is not None:
                    tags += ',misp:{}'.format(__sessions__.current.misp_event.event.id)
                else:
                    tags = 'misp:{}'.format(__sessions__.current.misp_event.event.id)

            # Try to store file object into database.
            status = Database().add(obj=obj, tags=tags)
            if status:
                # If succeeds, store also in the local repository.
                # If something fails in the database (for example unicode strings)
                # we don't want to have the binary lying in the repository with no
                # associated database record.
                new_path = store_sample(obj)
                self.log("success", "Stored file \"{0}\" to {1}".format(obj.name, new_path))

            else:
                return False

            # Delete the file if requested to do so.
            if args.delete:
                try:
                    os.unlink(obj.path)
                except Exception as e:
                    self.log('warning', "Failed deleting file: {0}".format(e))

            return True

        # If the user specified the --folder flag, we walk recursively and try
        # to add all contained files to the local repository.
        # This is note going to open a new session.
        # TODO: perhaps disable or make recursion optional?
        if args.folder is not None:
            # Check if the specified folder is valid.
            if os.path.isdir(args.folder):
                # Walk through the folder and subfolders.
                for dir_name, dir_names, file_names in walk(args.folder):
                    # Add each collected file.
                    for file_name in file_names:
                        file_path = os.path.join(dir_name, file_name)

                        if not os.path.exists(file_path):
                            continue
                        # Check if file is not zero.
                        if not os.path.getsize(file_path) > 0:
                            continue

                        # Check if the file name matches the provided pattern.
                        if args.file_name:
                            if not fnmatch.fnmatch(file_name, args.file_name):
                                # self.log('warning', "Skip, file \"{0}\" doesn't match the file name pattern".format(file_path))
                                continue

                        # Check if the file type matches the provided pattern.
                        if args.file_type:
                            if args.file_type not in File(file_path).type:
                                # self.log('warning', "Skip, file \"{0}\" doesn't match the file type".format(file_path))
                                continue

                        # Check if file exceeds maximum size limit.
                        if args.file_size:
                            # Obtain file size.
                            if os.path.getsize(file_path) > args.file_size:
                                self.log('warning', "Skip, file \"{0}\" is too big".format(file_path))
                                continue

                        file_obj = File(file_path)

                        # Add file.
                        add_file(file_obj, args.tags)
                        if add_file and __config__.get('autorun').enabled:
                            autorun_module(file_obj.sha256)
                            # Close the open session to keep the session table clean
                            __sessions__.close()

            else:
                self.log('error', "You specified an invalid folder: {0}".format(args.folder))
        # Otherwise we try to store the currently opened file, if there is any.
        else:
            if __sessions__.is_set():
                if __sessions__.current.file.size == 0:
                    self.log('warning', "Skip, file \"{0}\" appears to be empty".format(__sessions__.current.file.name))
                    return False

                # Add file.
                if add_file(__sessions__.current.file, args.tags):
                    # TODO: review this. Is there a better way?
                    # Open session to the new file.
                    Open().run(*[__sessions__.current.file.sha256])
                    if __config__.get('autorun').enabled:
                        autorun_module(__sessions__.current.file.sha256)
            else:
                self.log('error', "No open session. This command expects a file to be open.")
