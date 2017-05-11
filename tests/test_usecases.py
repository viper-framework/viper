# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.
from __future__ import unicode_literals

import os
import re
import sys
from shutil import copyfile

from hashlib import sha256

import pytest
from tests.conftest import FIXTURE_DIR

from viper.core.session import __sessions__
from viper.core.ui import commands
from viper.common.exceptions import Python2UnsupportedUnicode

try:
    from unittest import mock
except ImportError:
    # Python2
    import mock


class TestUseCases:

    def teardown_method(self):
        __sessions__.close()

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename, name", [
        ("chromeinstall-8u31.exe", "chromeinstall-8u31.exe"),
        ("string_handling/with blank.txt", "with blank.txt"),
        ])
    def test_store(self, capsys, filename, name):
        # use cleandir fixture operate on clean ./ local dir
        copyfile(os.path.join(FIXTURE_DIR, filename), os.path.join(".", os.path.basename(filename)))
        commands.Open().run('-f', os.path.join(".", os.path.basename(filename)))
        commands.Store().run()
        if sys.version_info <= (3, 0):
            in_fct = 'viper.core.ui.commands.input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='y'):
            commands.Delete().run()
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert not re.search(r".*Unable to store file.*", out)
        assert re.search(r".*{}.*".format(name), lines[1])
        assert re.search(r".*Running command.*", lines[5])
        assert re.search(r".*Deleted opened file.*", lines[7])

    @pytest.mark.skipif(sys.version_info >= (3, 0), reason="requires python2")
    @pytest.mark.xfail(raises=Python2UnsupportedUnicode)
    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename, name", [
        ("string_handling/dümmy.txt", "dümmy.txt")
        ])
    def test_store_unicode_py2(self, capsys, filename, name):
        # use cleandir fixture operate on clean ./ local dir
        copyfile(os.path.join(FIXTURE_DIR, filename), os.path.join(".", os.path.basename(filename)))
        commands.Open().run('-f', os.path.join(".", os.path.basename(filename)))
        commands.Store().run()
        if sys.version_info <= (3, 0):
            in_fct = 'viper.core.ui.commands.input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='y'):
            commands.Delete().run()
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert not re.search(r".*Unable to store file.*", out)
        assert re.search(r".*{}.*".format(name), lines[1])
        assert re.search(r".*Running command.*", lines[5])
        assert re.search(r".*Deleted opened file.*", lines[7])

    @pytest.mark.skipif(sys.version_info < (3, 3), reason="requires at least python3.3")
    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename, name", [
        ("string_handling/dümmy.txt", "dümmy.txt")
        ])
    def test_store_unicode_py3(self, capsys, filename, name):
        # use cleandir fixture operate on clean ./ local dir
        copyfile(os.path.join(FIXTURE_DIR, filename), os.path.join(".", os.path.basename(filename)))
        commands.Open().run('-f', os.path.join(".", os.path.basename(filename)))
        commands.Store().run()
        if sys.version_info <= (3, 0):
            in_fct = 'viper.core.ui.commands.input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='y'):
            commands.Delete().run()
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert not re.search(r".*Unable to store file.*", out)
        assert re.search(r".*{}.*".format(name), lines[1])
        assert re.search(r".*Running command.*", lines[5])
        assert re.search(r".*Deleted opened file.*", lines[7])

    @pytest.mark.skipif(sys.version_info >= (3, 0), reason="requires python2")
    @pytest.mark.xfail(raises=Python2UnsupportedUnicode)
    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_store_all_py2(self, capsys, filename):
        commands.Open().run('-f', os.path.join(FIXTURE_DIR, filename))
        commands.Store().run()
        commands.Store().run('-f', FIXTURE_DIR)
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*appears to be already stored.*", out)
        assert re.search(r".*Skip, file \"chromeinstall-8u31.exe\" appears to be already stored.*", out)

    @pytest.mark.skipif(sys.version_info < (3, 3), reason="requires at least python3.3")
    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_store_all_py3(self, capsys, filename):
        commands.Open().run('-f', os.path.join(FIXTURE_DIR, filename))
        commands.Store().run()
        commands.Store().run('-f', FIXTURE_DIR)
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*appears to be already stored.*", out)
        assert re.search(r".*Skip, file \"chromeinstall-8u31.exe\" appears to be already stored.*", out)

    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_open(self, capsys, filename):
        with open(os.path.join(FIXTURE_DIR, filename), 'rb') as f:
            hashfile = sha256(f.read()).hexdigest()
        commands.Open().run(hashfile)
        commands.Info().run()
        commands.Close().run()
        out, err = capsys.readouterr()
        lines = out.split("\n")

        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*| SHA1     | 56c5b6cd34fa9532b5a873d6bdd4380cfd102218.*", lines[11])

    @pytest.mark.parametrize("filename", ["chromeinstall-8u31.exe"])
    def test_find(self, capsys, filename):
        with open(os.path.join(FIXTURE_DIR, filename), 'rb') as f:
            data = f.read()
            hashfile_sha = sha256(data).hexdigest()
        commands.Find().run('all')
        commands.Find().run('sha256', hashfile_sha)
        commands.Open().run('-l', '1')
        commands.Close().run()
        commands.Tags().run('-a', 'blah')
        commands.Find().run('-t')
        commands.Tags().run('-d', 'blah')
        out, err = capsys.readouterr()

        assert re.search(r".*EICAR.com.*", out)
        assert re.search(r".*{0}.*".format(filename), out)
        assert re.search(r".*Tag.*|.*# Entries.*", out)

    def test_stats(self, capsys):
        commands.Stats().run()
        out, err = capsys.readouterr()

        assert re.search(r".*Projects.*Name | Count.*", out)
