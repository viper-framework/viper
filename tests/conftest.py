# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import pytest
import tempfile
import os
import shutil

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'viper-test-files/test_files',)


@pytest.fixture()
def cleandir():
    newpath = tempfile.mkdtemp(prefix="viper_tests_tmp_")
    os.chdir(newpath)
    yield
    shutil.rmtree(newpath)


@pytest.fixture()
def cleandir_keep():
    newpath = tempfile.mkdtemp(prefix="viper_tests_tmp_")
    os.chdir(newpath)
    yield
