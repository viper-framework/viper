# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re

import pytest

from tests.conftest import FIXTURE_DIR
from viper.common.abstracts import ArgumentErrorCallback, Module
from viper.core.plugins import __modules__
from viper.core.session import __sessions__

emailparse = __modules__["email"]["obj"]


class TestEmailParse:
    def test_init(self):
        instance = emailparse()
        assert isinstance(instance, emailparse)
        assert isinstance(instance, Module)

    def test_args_exception(self):
        instance = emailparse()
        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*Parse eml and msg email files.*")

    def test_run_help(self, capsys):
        instance = emailparse()
        instance.set_commandline(["--help"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_short_help(self, capsys):
        instance = emailparse()
        instance.set_commandline(["-h"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_invalid_option(self, capsys):
        instance = emailparse()
        instance.set_commandline(["invalid"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*unrecognized arguments:.*", out)

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("junk.eml", [r".*Google Award 2017.pdf.*"]),
            ("junk2.eml", [r".*Photocopy04062017.*"]),
            ("junk3.eml", [r".*http://www.earthworksjax.com.*"]),
            ("unicode.msg", [r".*raisedva.tif.*"]),
        ],
    )
    def test_all(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = emailparse()
        instance.command_line = ["-a"]

        instance.run()
        out, err = capsys.readouterr()

        for e in expected:
            assert re.search(e, out)
