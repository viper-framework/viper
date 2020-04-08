# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re

import pytest
from tests.conftest import FIXTURE_DIR

from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

from viper.core.session import __sessions__
from viper.core.plugins import __modules__

swf = __modules__['swf']["obj"]


class TestSWF:
    def test_init(self):
        instance = swf()
        assert isinstance(instance, swf)
        assert isinstance(instance, Module)

    def test_args_exception(self):
        instance = swf()
        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*Parse, analyze and decompress Flash objects.*")

    def test_run_help(self, capsys):
        instance = swf()
        instance.set_commandline(["--help"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_short_help(self, capsys):
        instance = swf()
        instance.set_commandline(["-h"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_invalid_option(self, capsys):
        instance = swf()
        instance.set_commandline(["invalid"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*unrecognized arguments:.*", out)

    @pytest.mark.parametrize("filename", ["ObjectPool-_1398590705-Contents-FLASH-Decompressed1"])
    def test_meta(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = swf()
        instance.command_line = []

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*The opened file doesn't appear to be compressed.*", out)
