# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import pytest
from tests.conftest import FIXTURE_DIR

from viper.core.database import Malware, Tag, Note, Analysis, Database
from viper.common.objects import File
from viper.common.exceptions import Python2UnsupportedUnicode


class TestMalware:
    def test_init(self):
        instance = Malware(md5="ad7b9c14083b52bc532fba5948342b98",
                           sha1="ee8cbf12d87c4d388f09b4f69bed2e91682920b5",
                           crc32="C1BA11D1",
                           sha256="17f746d82695fa9b35493b41859d39d786d32b23a9d2e00f4011dec7a02402ae",
                           sha512="e12aad20c824187b39edb3c7943709290b5ddbf1b4032988db46f2e86da3cf7e7783f78c82e4dc5da232f666b8f9799a260a1f8e2694eb4d0cdaf78da710fde1",  # noqa
                           size="302592")
        assert isinstance(instance, Malware)
        assert instance.__repr__() == "<Malware ('None','ad7b9c14083b52bc532fba5948342b98')>"

    def test_to_dict(self):
        instance = Malware(md5="ad7b9c14083b52bc532fba5948342b98",
                           sha1="ee8cbf12d87c4d388f09b4f69bed2e91682920b5",
                           crc32="C1BA11D1",
                           sha256="17f746d82695fa9b35493b41859d39d786d32b23a9d2e00f4011dec7a02402ae",
                           sha512="e12aad20c824187b39edb3c7943709290b5ddbf1b4032988db46f2e86da3cf7e7783f78c82e4dc5da232f666b8f9799a260a1f8e2694eb4d0cdaf78da710fde1",  # noqa
                           size="302592")
        assert isinstance(instance, Malware)
        assert instance.to_dict() == {'id': None,
                                      'md5': "ad7b9c14083b52bc532fba5948342b98",
                                      'sha1': "ee8cbf12d87c4d388f09b4f69bed2e91682920b5",
                                      'crc32': "C1BA11D1",
                                      'sha256': "17f746d82695fa9b35493b41859d39d786d32b23a9d2e00f4011dec7a02402ae",
                                      'sha512': "e12aad20c824187b39edb3c7943709290b5ddbf1b4032988db46f2e86da3cf7e7783f78c82e4dc5da232f666b8f9799a260a1f8e2694eb4d0cdaf78da710fde1",  # noqa
                                      'size': "302592",
                                      'type': None,
                                      'mime': None,
                                      'ssdeep': None,
                                      'name': None,
                                      'created_at': None,
                                      'parent_id': None}


class TestTag:
    def test_init(self):
        instance = Tag(tag="spam")
        assert isinstance(instance, Tag)
        assert instance.__repr__() == "<Tag ('None','spam')>"

    def test_to_dict(self):
        instance = Tag(tag="eggs")
        assert isinstance(instance, Tag)
        assert instance.to_dict() == {'id': None, 'tag': 'eggs'}


class TestNote:
    def test_init(self):
        instance = Note(title="MyTitle", body="MyBody")
        assert isinstance(instance, Note)
        assert instance.__repr__() == "<Note ('None','MyTitle')>"

    def test_to_dict(self):
        instance = Note(title="MyTitle", body="MyBody")
        assert isinstance(instance, Note)
        assert instance.to_dict() == {'id': None, 'title': "MyTitle", 'body': 'MyBody'}


class TestAnalysis:
    def test_init(self):
        instance = Analysis(cmd_line="some_cmd -a", results="Foobar")
        assert isinstance(instance, Analysis)
        assert instance.__repr__() == "<Analysis ('None','some_cmd -a')>"

    def test_to_dict(self):
        instance = Analysis(cmd_line="some_cmd -a", results="Foobar")
        assert isinstance(instance, Analysis)
        assert instance.to_dict() == {'id': None,
                                      'cmd_line': "some_cmd -a",
                                      'results': 'Foobar',
                                      'stored_at': None}


class TestDatabase:
    def test_init(self):
        instance = Database()
        assert isinstance(instance, Database)
        assert instance.__repr__() == "<Database>"

    @pytest.mark.parametrize("filename, name", [
        ("string_handling/ascii.txt", "ascii.txt"),
        ("string_handling/with blank.txt", "with blank.txt")
        ])
    def test_add(self, capsys, filename, name):
        f = File(os.path.join(FIXTURE_DIR, filename))

        instance = Database()
        ret = instance.add(f)
        assert ret is True

    @pytest.mark.skipif(sys.version_info >= (3, 0), reason="requires python2")
    @pytest.mark.xfail(raises=Python2UnsupportedUnicode)
    @pytest.mark.parametrize("filename, name", [
        ("string_handling/dümmy.txt", "dümmy.txt"),
        ])
    def test_add_unicode_py2(self, capsys, filename, name):
        f = File(os.path.join(FIXTURE_DIR, filename))

        instance = Database()
        ret = instance.add(f)
        assert ret is True

    @pytest.mark.skipif(sys.version_info < (3, 3), reason="requires at least python3.3")
    @pytest.mark.parametrize("filename, name", [
        ("string_handling/dümmy.txt", "dümmy.txt")
        ])
    def test_add_unicode_py3(self, capsys, filename, name):
        f = File(os.path.join(FIXTURE_DIR, filename))

        instance = Database()
        ret = instance.add(f)
        assert ret is True
