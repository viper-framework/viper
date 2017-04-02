# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import pytest
from tests.conftest import FIXTURE_DIR

from viper.modules import rat
from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

from viper.core.session import __sessions__


class TestRAT:

    def teardown_method(self):
        __sessions__.close()

    def test_init(self):
        instance = rat.RAT()
        assert isinstance(instance, Module)

    def test_args_exception(self):
        instance = rat.RAT()
        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*Extract information from known RAT families.*")

    def test_run_help(self, capsys):
        instance = rat.RAT()
        instance.set_commandline(["--help"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_short_help(self, capsys):
        instance = rat.RAT()
        instance.set_commandline(["-h"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_list(self, capsys):
        instance = rat.RAT()
        instance.set_commandline(["-l"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*List of available RAT modules:.*", out)

    def test_run_auto_no_session(self, capsys):
        instance = rat.RAT()
        instance.set_commandline(["-a"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r'.*No open session.*', out)

    def test_run_family_no_session(self, capsys):
        instance = rat.RAT()
        instance.set_commandline(["-f", "adwind"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r'.*No open session.*', out)

    @pytest.mark.parametrize("filename, expected", [
        ("chromeinstall-8u31.exe", False),
    ])
    def test_run_family_no_module(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))

        instance = rat.RAT()
        instance.run()
        out, err = capsys.readouterr()
        instance.set_commandline(["-f", "foobar"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r'.*There is no module for family.*', out)

    @pytest.mark.parametrize("filename, expected", [
        ("chromeinstall-8u31.exe", False),
        # ("chromeinstall-8u31.exe", True),
    ])
    def test_run_auto(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))

        instance = rat.RAT()
        instance.set_commandline(["-a"])

        instance.run()
        out, err = capsys.readouterr()
        if expected:
            assert re.search(r'.*Automatically detected supported.*', out)
        else:
            assert re.search(r'.*No known RAT detected.*', out)

    @pytest.mark.parametrize("filename, expected", [
        ("chromeinstall-8u31.exe", False),
        # ("chromeinstall-8u31.exe", True),
    ])
    def test_run_family_adwind(self, capsys, filename, expected):
        # FIXME: this test isn't really useful.
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))

        instance = rat.RAT()
        instance.set_commandline(["-f", "adwind"])

        instance.run()
        out, err = capsys.readouterr()
        if expected:
            assert re.search(r'.*Automatically detected supported.*', out)
        else:
            assert re.search(r'.*No Configuration Detected.*', out)
