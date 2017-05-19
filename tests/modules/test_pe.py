# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
from datetime import datetime

import pytest
from tests.conftest import FIXTURE_DIR

from viper.modules import pe
from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

from viper.core.session import __sessions__


class TestPE:
    def test_init(self):
        instance = pe.PE()
        assert isinstance(instance, pe.PE)
        assert isinstance(instance, Module)

    def test_args_exception(self):
        instance = pe.PE()

        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*Extract information from PE32 headers.*")

    def test_run_help(self, capsys):
        instance = pe.PE()
        instance.set_commandline(["--help"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_short_help(self, capsys):
        instance = pe.PE()
        instance.set_commandline(["-h"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_invalid_option(self, capsys):
        instance = pe.PE()
        instance.set_commandline(["invalid"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*argument subname: invalid choice.*", out)

    @pytest.mark.parametrize("filename, expected", [
        ("chromeinstall-8u31.exe", "1418884325 ({0})".format(datetime(2014, 12, 18, 6, 32, 5))),
    ])
    def test_compiletime(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = pe.PE()
        instance.command_line = ["compiletime"]

        instance.run()
        out, err = capsys.readouterr()
        lines = out.split("\n")
        assert re.search(r".*Session opened*", lines[0])
        assert re.search(r".*Compile Time*", lines[1])
        assert re.search(r".*{}*".format(expected), lines[1])
        assert instance.result_compile_time == expected

    @pytest.mark.parametrize("filename, expected", [
        ("chromeinstall-8u31.exe", 3),
    ])
    def test_sections(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = pe.PE()
        instance.command_line = ["sections"]

        instance.run()
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened*", lines[0])
        assert re.search(r".*PE Sections.*", lines[1])
        assert len(instance.result_sections) == expected

    @pytest.mark.parametrize("filename, expected", [
        ("513a6e4e94369c64cab49324cd49c44137d2b66967bb6d16394ab145a8e32c45", 'e8fbb742e0d29f1ed5f587b3b769b426'),
    ])
    def test_security(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = pe.PE()
        instance.command_line = ["security"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*{}*".format(expected), out)

    @pytest.mark.parametrize("filename, expected", [("cmd.exe", r".*Probable language:.*C.*")])
    def test_language(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = pe.PE()
        instance.command_line = ["language"]

        instance.run()
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(expected, lines[1])

    @pytest.mark.parametrize("filename, expected", [
        ("513a6e4e94369c64cab49324cd49c44137d2b66967bb6d16394ab145a8e32c45",
         r'.*2ab445d9a9ffeaab2ab3da4a68de3578.*86bbbd7c06317e171949a0566cdd05ae.*5c073d8e75dc926dd04bc73e32d41beb.*a19a2658ba69030c6ac9d11fd7d7e3c1.*'),
    ])
    def test_resources(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = pe.PE()
        instance.command_line = ["resources"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(expected, expected)

    # @pytest.mark.parametrize("filename,expected", [
    #     ("cmd.exe", 9),
    # ])
    # def test_sections(self, filename, expected):
    #     __sessions__.new(os.path.join(FIXTURE_DIR, filename))
    #
    #     instance = pe.PE()
    #     instance.sections()
    #
    #     assert 0
