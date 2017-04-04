# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re

from hashlib import sha256

import pytest
from tests.conftest import FIXTURE_DIR

from viper.core.session import __sessions__
from viper.core.ui import commands


class TestUseCases:

    def teardown_method(self):
        __sessions__.close()

    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_store(self, capsys, filename):
        instance = commands.Commands()
        instance.cmd_open('-f', os.path.join(FIXTURE_DIR, filename))
        instance.cmd_store()
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*Running command.*", lines[5])

    def test_store_all(self, capsys):
        instance = commands.Commands()
        instance.cmd_store('-f', FIXTURE_DIR)
        out, err = capsys.readouterr()
        assert re.search(r".*Skip, file \"chromeinstall-8u31.exe\" appears to be already stored.*", out)

    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_open(self, capsys, filename):
        with open(os.path.join(FIXTURE_DIR, filename), 'rb') as f:
            hashfile = sha256(f.read()).hexdigest()
        instance = commands.Commands()
        instance.cmd_open(hashfile)
        instance.cmd_info()
        instance.cmd_close()
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*| SHA1     | 56c5b6cd34fa9532b5a873d6bdd4380cfd102218.*", lines[11])

    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_find(self, capsys, filename):
        with open(os.path.join(FIXTURE_DIR, filename), 'rb') as f:
            data = f.read()
            hashfile_sha = sha256(data).hexdigest()
        instance = commands.Commands()
        instance.cmd_find('all')
        instance.cmd_find('sha256', hashfile_sha)
        out, err = capsys.readouterr()

        assert re.search(r".*EICAR.com.*", out)
        assert re.search(r".*{0}.*".format(filename), out)

    def test_stats(self, capsys):
        instance = commands.Commands()
        instance.cmd_stats()
        out, err = capsys.readouterr()

        assert re.search(r".*Projects.*Name | Count.*", out)
