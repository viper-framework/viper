# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import platform
from typing import Any

from viper.common.abstracts import Command
from viper.common.version import VIPER_VERSION
from viper.core.config import cfg
from viper.core.database import Database
from viper.core.projects import project


class About(Command):
    """
    This command prints some useful information regarding the running
    Viper instance
    """

    cmd = "about"
    description = "Show information about this Viper instance"

    def run(self, *args: Any):
        try:
            self.parser.parse_args(args)
        except SystemExit:
            return

        rows = list()
        rows.append(["Viper Version", VIPER_VERSION])
        rows.append(["Python Version", platform.python_version()])
        # TODO: I let viper.li expire (sigh), so will have to commend this.
        # rows.append(["Homepage", "https://viper.li"])
        rows.append(
            ["Issue Tracker", "https://github.com/viper-framework/viper/issues"]
        )

        self.log("table", {"columns": ["About", ""], "rows": rows})

        rows = list()
        rows.append(["Configuration File", cfg.config_file])

        module_path = os.path.join(cfg.paths.module_path, "modules")

        if project.name:
            rows.append(["Active Project", project.name])
            rows.append(["Storage Path", project.path])
            rows.append(["Module Path", module_path])
            rows.append(["Database Path", str(Database().engine.url)])
        else:
            rows.append(["Active Project", "default"])
            rows.append(["Storage Path", project.path])
            rows.append(["Module Path", module_path])
            rows.append(["Database Path", str(Database().engine.url)])

        self.log("table", {"columns": ["Configuration", ""], "rows": rows})
