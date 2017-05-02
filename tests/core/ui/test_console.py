# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from tests.conftest import FIXTURE_DIR
from viper.core.session import __sessions__
from viper.core.ui import console
from viper.common.objects import MispEvent
try:
    from unittest import mock
except ImportError:
    # Python2
    import mock
import sys
import re
import pytest
import os


class TestConsole:

    def teardown_method(self):
        __sessions__.close()

    def test_init(self):
        instance = console.Console()
        assert isinstance(instance, console.Console)

    def test_start(self, capsys):
        instance = console.Console()
        if sys.version_info <= (3, 0):
            in_fct = 'viper.core.ui.console.input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='help;exit'):
            instance.start()
        out, err = capsys.readouterr()
        assert re.search(r".*You have .* files in your .* repository.*", out)
        assert re.search(r".* Commands.*", out)
        assert re.search(r".* Modules.*", out)

    @pytest.mark.usefixtures("cleandir")
    def test_redirect(self, capsys):
        instance = console.Console()
        if sys.version_info <= (3, 0):
            in_fct = 'viper.core.ui.console.input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='help > ./redirect;exit'):
            instance.start()
        out, err = capsys.readouterr()
        assert re.search(r".*Output written to  ./redirect.*", out)

    @pytest.mark.parametrize("filename,command,expected",
                             [("chromeinstall-8u31.exe", 'pe imphash', '697c52d3bf08cccfd62da7bc503fdceb'),
                              ('58e902cd-dae8-49b9-882b-186c02de0b81.json', 'misp --off show', 'Session opened on MISP event 6322')])
    def test_opened_session(self, capsys, filename, command, expected):
        if filename == "chromeinstall-8u31.exe":
            __sessions__.new(path=os.path.join(FIXTURE_DIR, filename))
        elif filename == '58e902cd-dae8-49b9-882b-186c02de0b81.json':
            me = MispEvent(os.path.join(FIXTURE_DIR, filename), True)
            __sessions__.new(misp_event=me)
        instance = console.Console()
        if sys.version_info <= (3, 0):
            in_fct = 'viper.core.ui.console.input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='{};exit'.format(command)):
            instance.start()
        out, err = capsys.readouterr()
        assert re.search(r".*{}.*".format(expected), out)
