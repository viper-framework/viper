# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from typing import Any

from viper.common.abstracts import Command
from viper.core.sessions import sessions


class Info(Command):
    """
    This command returns information on the open session. It returns details
    on the file (e.g. hashes) and other information that might available from
    the database.
    """

    cmd = "info"
    description = "Show information on the open file"

    def run(self, *args: Any):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if not sessions.is_set():
            self.log(
                "error", "No open session. This command expects a file to be open."
            )
            return

        self.log(
            "table",
            {
                "columns": ["Key", "Value"],
                "rows": [
                    ["Name", sessions.current.file.name],
                    ["Tags", sessions.current.file.tags],
                    ["Path", sessions.current.file.path],
                    ["Size", str(sessions.current.file.size)],
                    ["Type", sessions.current.file.type],
                    ["Mime", sessions.current.file.mime],
                    ["MD5", sessions.current.file.md5],
                    ["SHA1", sessions.current.file.sha1],
                    ["SHA256", sessions.current.file.sha256],
                    ["SHA512", sessions.current.file.sha512],
                    ["SSdeep", sessions.current.file.ssdeep],
                    ["CRC32", sessions.current.file.crc32],
                    ["Parent", sessions.current.file.parent],
                    ["Children", sessions.current.file.children],
                ],
            },
        )
