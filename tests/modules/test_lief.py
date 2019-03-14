# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
from datetime import datetime

import pytest
from tests.conftest import FIXTURE_DIR

from viper.modules import lief
from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

from viper.core.session import __sessions__

class TestLIEF:
    def test_init(self):
        instance = lief.Lief()
        assert isinstance(instance, lief.Lief)
        assert isinstance(instance, Module)

    def test_args_exception(self):
        instance = lief.Lief()

        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*extract information from ELF, PE, MachO, DEX, OAT, ART and VDEX.*")

    def test_run_help(self, capsys):
        instance = lief.Lief()
        instance.set_commandline(["--help"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_short_help(self, capsys):
        instance = lief.Lief()
        instance.set_commandline(["-h"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_invalid_option(self, capsys):
        instance = lief.Lief()
        instance.set_commandline(["invalid"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*argument subname: invalid choice.*", out)

    @pytest.mark.parametrize("filename, expected", [
        ("elf-Linux-x64-bash", 3),
    ])
    def test_sections_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--sections"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*Sections :.*", out)
    
    @pytest.mark.parametrize("filename, expected", [
        ("MachO-OSX-x64-ls", 3),
    ])
    def test_sections_macho(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--sections"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*MachO sections :.*", out)
    
    @pytest.mark.parametrize("filename, expected", [
        ("whoami.exe", 3),
    ])
    def test_sections_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--sections"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*PE sections :.*", out)
    
    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", 3),
    ])
    def test_sections_oat(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--sections"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*Sections :.*", out)
