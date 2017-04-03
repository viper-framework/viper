# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.core.ui import commands


class TestCommands:

    def test_init(self):
        instance = commands.Commands()
        assert isinstance(instance, commands.Commands)

    def test_help(self):
        instance = commands.Commands()
        instance.cmd_help()
        instance.cmd_clear()
        instance.cmd_close()
