# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Command
from viper.core.session import __sessions__


class Info(Command):
    """
    This command returns information on the open session. It returns details
    on the file (e.g. hashes) and other information that might available from
    the database.
    """
    cmd = "info"
    description = "Show information on the opened file"

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            return

        self.log('table', dict(
            header=['Key', 'Value'],
            rows=[
                ['Name', __sessions__.current.file.name],
                ['Tags', __sessions__.current.file.tags],
                ['Path', __sessions__.current.file.path],
                ['Size', __sessions__.current.file.size],
                ['Type', __sessions__.current.file.type],
                ['Mime', __sessions__.current.file.mime],
                ['MD5', __sessions__.current.file.md5],
                ['SHA1', __sessions__.current.file.sha1],
                ['SHA256', __sessions__.current.file.sha256],
                ['SHA512', __sessions__.current.file.sha512],
                ['SSdeep', __sessions__.current.file.ssdeep],
                ['CRC32', __sessions__.current.file.crc32],
                ['Parent', __sessions__.current.file.parent],
                ['Children', __sessions__.current.file.children]
            ]
        ))
