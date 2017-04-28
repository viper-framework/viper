# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import sys
from shutil import copyfile

from hashlib import sha256

import pytest
from tests.conftest import FIXTURE_DIR

from viper.core.session import __sessions__
from viper.core.ui import commands

try:
    from unittest import mock
except ImportError:
    # Python2
    import mock


class TestUseCases:

    def teardown_method(self):
        __sessions__.close()

    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_store(self, capsys, filename):
        instance = commands.Commands()
        copyfile(os.path.join(FIXTURE_DIR, filename), os.path.join(FIXTURE_DIR, 'copy_' + filename))
        instance.cmd_open('-f', os.path.join(FIXTURE_DIR, 'copy_' + filename))
        instance.cmd_store()
        if sys.version_info <= (3, 0):
            in_fct = 'viper.core.ui.commands.input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='y'):
            instance.cmd_delete()
        os.remove(os.path.join(FIXTURE_DIR, 'copy_' + filename))
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*Running command.*", lines[5])
        assert re.search(r".*Deleted opened file.*", lines[7])

    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_store_all(self, capsys, filename):
        instance = commands.Commands()
        instance.cmd_open('-f', os.path.join(FIXTURE_DIR, filename))
        instance.cmd_store()
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
        instance.cmd_open('-l', '1')
        instance.cmd_close()
        instance.cmd_tags('-a', 'blah')
        instance.cmd_find('-t')
        instance.cmd_tags('-d', 'blah')
        out, err = capsys.readouterr()

        assert re.search(r".*EICAR.com.*", out)
        assert re.search(r".*{0}.*".format(filename), out)
        assert re.search(r".*Tag.*|.*# Entries.*", out)

    def test_stats(self, capsys):
        instance = commands.Commands()
        instance.cmd_stats()
        out, err = capsys.readouterr()

        assert re.search(r".*Projects.*Name | Count.*", out)
