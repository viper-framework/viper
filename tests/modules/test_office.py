# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re

import pytest
from tests.conftest import FIXTURE_DIR

from viper.modules import office
from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

from viper.core.session import __sessions__


class TestOffice:
    def test_init(self):
        instance = office.Office()
        assert isinstance(instance, office.Office)
        assert isinstance(instance, Module)

    def test_args_exception(self):
        instance = office.Office()
        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*Office Document Parser.*")

    def test_run_help(self, capsys):
        instance = office.Office()
        instance.set_commandline(["--help"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_short_help(self, capsys):
        instance = office.Office()
        instance.set_commandline(["-h"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_invalid_option(self, capsys):
        instance = office.Office()
        instance.set_commandline(["invalid"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*unrecognized arguments:.*", out)

    @pytest.mark.parametrize("filename", ["Douglas-Resume.doc"])
    def test_meta(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = office.Office()
        instance.command_line = ["-m"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*comments .*| htsgraghtfgyrwthwwb*", out)
        assert re.search(r".*create_time .*| 2017-03-08 16:00:00*", out)
        assert re.search(r".*last_saved_time .*| 2017-04-09 19:03:00.*", out)

    @pytest.mark.parametrize("filename", ["Douglas-Resume.doc"])
    def test_oleid(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = office.Office()
        instance.command_line = ["-o"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Macros .*| True.*", out)

    @pytest.mark.parametrize("filename", ["Douglas-Resume.doc"])
    def test_streams(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = office.Office()
        instance.command_line = ["-s"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Macros/kfjtir .* 2017-04-09 19:03:45.905000 | 2017-04-09 19:03:45.920000.*", out)

    @pytest.mark.parametrize("filename", ["Douglas-Resume.doc"])
    def test_vba(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = office.Office()
        instance.command_line = ["-v"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*ojerc.bas.*", out)
        assert re.search(r".*kgfoto.frm.*", out)
        assert re.search(r".*zxsfg.bas.*", out)
        assert re.search(r".*May download files from the Internet using PowerShell.*", out)
        assert re.search(r".*.paya.exe*", out)
        assert re.search(r".*.\x08\x00+3q\xb5 .*| 08002B3371B5*", out)

    @pytest.mark.parametrize("filename", ["Douglas-Resume.doc"])
    def test_export(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = office.Office()
        instance.command_line = ["-e", 'out_all']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Saved stream to out_all/Macros-VBA-kfjtir.*", out)

    @pytest.mark.parametrize("filename", ["Douglas-Resume.doc"])
    def test_code(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = office.Office()
        instance.command_line = ["-c", 'out_macro']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Writing VBA Code to out_macro.*", out)