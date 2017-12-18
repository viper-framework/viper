# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re

import pytest
from tests.conftest import FIXTURE_DIR

from viper.modules import fuzzy
from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

from viper.core.session import __sessions__


class TestFuzzy:
    def test_init(self):
        instance = fuzzy.Fuzzy()
        assert isinstance(instance, fuzzy.Fuzzy)
        assert isinstance(instance, Module)

    def test_args_exception(self):
        instance = fuzzy.Fuzzy()
        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*Search for similar files through fuzzy hashing.*")

    def test_run_help(self, capsys):
        instance = fuzzy.Fuzzy()
        instance.set_commandline(["--help"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_short_help(self, capsys):
        instance = fuzzy.Fuzzy()
        instance.set_commandline(["-h"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_invalid_option(self, capsys):
        instance = fuzzy.Fuzzy()
        instance.set_commandline(["invalid"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*unrecognized arguments:.*", out)

    def test_run_cluster(self, capsys):
        instance = fuzzy.Fuzzy()
        instance.set_commandline(['-c'])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*Generating clusters, this might take a while.*", out)

    @pytest.mark.parametrize("filename", ["cmd.exe"])
    def test_run_session(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = fuzzy.Fuzzy()
        instance.command_line = []

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*relevant matches found.*", out)
