# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import pytest
import tempfile
import os
import shutil
import sys

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'viper-test-files/test_files',)

collect_ignore = []
if sys.version_info < (3, 6,):
    collect_ignore.append('modules/test_misp.py')
    collect_ignore.append('modules/test_lief.py')


@pytest.fixture()
def cleandir():
    newpath = tempfile.mkdtemp(prefix="viper_tests_tmp_")
    old_cwd = os.getcwd()
    os.chdir(newpath)
    yield
    os.chdir(old_cwd)
    shutil.rmtree(newpath)
