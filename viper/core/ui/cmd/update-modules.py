# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import subprocess

from viper.common.abstracts import Command

class UpdateModules(Command):
    """
    This command downloads modules from the GitHub repository at
    https://github.com/viper-framework/viper-modules
    """
    cmd = "update-modules"
    description = "Download Viper modules from the community GitHub repository"

    def run(self, *args):
        self.log("info", "Updating modules...")

        dot_viper = os.path.join(os.path.expanduser("~"), ".viper")
        dot_viper_modules = os.path.join(dot_viper, "modules")

        if os.path.exists(dot_viper_modules):
            # Pull updates
            p = subprocess.Popen(["git", "pull"], cwd=dot_viper_modules)
            p.wait()
        else:
            # Clone the repository.
            p = subprocess.Popen(["git", "clone", "git@github.com:viper-framework/viper-modules.git",
                "modules"], cwd=dot_viper)
            p.wait()

        # Initialize submodules.
        p = subprocess.Popen(["git", "submodule", "init"], cwd=dot_viper_modules)
        p.wait()
        # Update submodules.
        p = subprocess.Popen(["git", "submodule", "update"], cwd=dot_viper_modules)
        p.wait()
        # Install dependencies.
        p = subprocess.Popen(["pip3", "install", "-r", "requirements.txt"], cwd=dot_viper_modules)
        p.wait()

        # TODO: this is terrible. We need to find a way to move __modules__
        # to  proper place that can be reloaded.
        self.log("info", "Modules updated, please relaunch `viper`.")
        sys.exit()
