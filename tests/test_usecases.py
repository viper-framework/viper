# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re

import pytest
from tests.conftest import FIXTURE_DIR

from viper.core.session import __sessions__
from viper.core.ui import commands


class TestUseCases:

    def teardown_method(self):
        __sessions__.close()

    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_store(self, capsys, filename):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = commands.Commands()
        instance.cmd_store()
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*Running command.*", lines[-2])
