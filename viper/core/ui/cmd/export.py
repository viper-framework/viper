# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import shutil
import getpass

from viper.common.abstracts import Command
from viper.core.archiver import Compressor
from viper.core.session import __sessions__


def get_password_twice():
    password = getpass.getpass('Password: ')
    if password == getpass.getpass('confirm Password: '):
        return password
    else:
        return None


class Export(Command):
    """
    This command will export the current session to file or zip.
    """
    cmd = "export"
    description = "Export the current session to file or zip"
    fs_path_completion = True

    def __init__(self):
        super(Export, self).__init__()

        self.parser.add_argument('-z', '--zip', action='store_true', help="Export session in a zip archive (PW support: No)")
        self.parser.add_argument('-7', '--sevenzip', action='store_true', help="Export session in a 7z archive (PW support: Yes)")
        self.parser.add_argument('-p', '--password', action='store_true', help="Protect archive with a password (PW) if supported")
        self.parser.add_argument('value', help="path or archive name")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        # This command requires a session to be opened.
        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            self.parser.print_usage()
            return

        # Check for valid export path.
        if args.value is None:
            self.parser.print_usage()
            return

        if args.zip and args.sevenzip:
            self.log('error', "Please select either -z or -7 not both, abort")

        store_path = os.path.join(args.value, __sessions__.current.file.name)

        if not args.zip and not args.sevenzip:
            # Abort if the specified path already exists
            if os.path.isfile(store_path):
                self.log('error', "Unable to export file: File exists: '{0}'".format(store_path))
                return

            if not os.path.isdir(args.value):
                try:
                    os.makedirs(args.value)
                except OSError as err:
                    self.log('error', "Unable to export file: {0}".format(err))
                    return

            try:
                shutil.copyfile(__sessions__.current.file.path, store_path)
            except IOError as e:
                self.log('error', "Unable to export file: {0}".format(e))
            else:
                self.log('info', "File exported to {0}".format(store_path))

            return
        elif args.zip:
            cls = "ZipCompressor"

        elif args.sevenzip:
            cls = "SevenZipSystemCompressor"
        else:
            cls = ""
            self.log('error', "Not implemented".format())

        c = Compressor()

        if args.password:
            if c.compressors[cls].supports_password:
                _password = get_password_twice()
                if not _password:
                    self.log('error', "Passwords did not match, abort")
                    return
                res = c.compress(__sessions__.current.file.path, file_name=__sessions__.current.file.name,
                                 archive_path=store_path, cls_name=cls, password=_password)
            else:
                self.log('warning', "ignoring password (not supported): {}".format(cls))
                res = c.compress(__sessions__.current.file.path, file_name=__sessions__.current.file.name,
                                 archive_path=store_path, cls_name=cls)

        else:
            res = c.compress(__sessions__.current.file.path, file_name=__sessions__.current.file.name,
                             archive_path=store_path, cls_name=cls)

        if res:
            self.log('info', "File archived and exported to {0}".format(c.output_archive_path))
        else:
            self.log('error', "Unable to export file: {0}".format(c.err))
