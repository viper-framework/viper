# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re

import pytest
from tests.conftest import FIXTURE_DIR

from viper.modules.macho import Macho, HAVE_MACHO
from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

from viper.core.session import __sessions__


class TestMacho:

    def teardown_method(self):
        __sessions__.close()

    def test_init(self):
        instance = Macho()
        assert isinstance(instance, Macho)
        assert isinstance(instance, Module)

    def test_have_macho(self):
        assert HAVE_MACHO is True

    def test_args_exception(self):
        instance = Macho()
        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*Get Macho OSX Headers.*")

    @pytest.mark.usefixtures("cleandir")
    def test_no_session(self, capsys):
        instance = Macho()
        instance.command_line = ["-a"]

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*No open session.*", out)

    @pytest.mark.parametrize("filename", ["whoami.exe"])
    def test_no_macho_file(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = Macho()
        instance.command_line = ["-hd"]

        instance.run()
        out, err = capsys.readouterr()

        lines = out.split("\n")
        assert re.search(r".*Not a Mach-O file.*", lines[1])

    @pytest.mark.parametrize("filename", ["MachO-OSX-x86-ls"])
    def test_no_argument(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = Macho()

        instance.run()
        out, err = capsys.readouterr()

        lines = out.split("\n")
        assert re.search(r".*Session opened on.*", lines[0])

    @pytest.mark.parametrize("filename,magic,cputype", [
        ("MachO-OSX-x86-ls", "0xfeedface - 32 bits", "0x7 - i386"),
        ("MachO-OSX-x64-ls", "0xfeedfacf - 64 bits", "0x1000007 - x86_64")
    ])
    def test_headers(self, capsys, filename, magic, cputype):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = Macho()
        instance.command_line = ["-hd"]

        instance.run()
        out, err = capsys.readouterr()

        lines = out.split("\n")
        assert re.search(r".*Headers", lines[1])
        assert re.search(r".*{}.*".format(magic), out)
        assert re.search(r".*{}.*".format(cputype), out)

    @pytest.mark.parametrize("filename,amount_segments", [
        ("MachO-OSX-x86-ls", 4)
    ])
    def test_segments(self, capsys, filename, amount_segments):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = Macho()
        instance.command_line = ["-sg"]

        instance.run()
        out, err = capsys.readouterr()

        lines = out.split("\n")
        assert re.search(r".*Segments \({}\)".format(amount_segments), lines[1])

    @pytest.mark.parametrize("filename,amount_commands", [
        ("MachO-OSX-x86-ls", 12),
    ])
    def test_load_commands(self, capsys, filename, amount_commands):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = Macho()
        instance.command_line = ["-lc"]

        instance.run()
        out, err = capsys.readouterr()

        lines = out.split("\n")
        assert re.search(r".*Load Commands \({}\)".format(amount_commands), lines[1])

    @pytest.mark.parametrize("filename", ["MachO-OSX-x86-ls"])
    def test_all(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = Macho()
        instance.command_line = ["-a"]

        instance.run()
        out, err = capsys.readouterr()

        lines = out.split("\n")
        assert re.search(r".*Headers", lines[1])
