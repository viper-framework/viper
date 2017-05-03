# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.
from __future__ import unicode_literals

import os
import re
import sys
import shutil

import pytest
from tests.conftest import FIXTURE_DIR

import subprocess
from collections import KeysView

from viper.core.archiver import Archiver, Compressor, Extractor
from viper.core.archiver import ZipExtractor


class TestUseCases:

    def teardown_method(self):
        pass


class TestArchiver:
    def test_init(self):
        instance = Archiver()
        assert isinstance(instance, Archiver)

    def test_check_min_python_version_fail(self):
        instance = Archiver()
        assert isinstance(instance, Archiver)
        instance.min_python_version = (9, 9)
        assert instance.check() is False

    def test_check_dependencies_python_fail(self):
        instance = Archiver()
        assert isinstance(instance, Archiver)
        instance.dependency_list_python = ["thismoduleisnotinstalled"]
        assert instance.check() is False

    def test_check_dependencies_python_version_fail(self):
        instance = Archiver()
        assert isinstance(instance, Archiver)
        instance.dependency_list_python = ["pytest>=999.0"]
        assert instance.check() is False

    def test_check_dependencies_system_fail(self):
        instance = Archiver()
        assert isinstance(instance, Archiver)
        instance.dependency_list_system = ["thisbinaryisnotinstalled"]
        assert instance.check() is False


class TestExtractor:
    def test_init(self):
        instance = Extractor()
        assert isinstance(instance, Extractor)
        assert isinstance(instance.extractors_by_extension, dict)
        assert isinstance(instance.extensions, (list, KeysView))
        assert "zip" in instance.extensions
        assert "bz2" in instance.extensions
        assert isinstance(instance.extractors, dict)
        assert "ZipExtractor" in instance.extractors
        assert isinstance(instance.extractors["ZipExtractor"], ZipExtractor)
        assert isinstance(instance.extractors["ZipExtractor"].summary, dict)
        assert instance.extractors["ZipExtractor"].summary["cls_name"] == 'ZipExtractor'
        assert instance.extractors["ZipExtractor"].summary["extensions"] == ['zip']
        assert instance.extractors["ZipExtractor"].summary["password"] is True
        assert instance.extractors["ZipExtractor"].summary["title"] == "Zip"
        assert isinstance(instance.extractors_by_extension, dict)
        assert isinstance(instance.extractors_by_extension["zip"], list)

    @pytest.mark.usefixtures("cleandir")
    def test_archive_does_not_exist(self, capsys):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path="/foobar97839872")
        assert res is False
        assert re.search("file does not exist", instance.err)
        assert os.listdir(os.getcwd()) == []

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", [
        "archiver/Mac.zip",
        "archiver/Mac.pdf.gz",
        "archiver/Mac.pdf.bz2",
        "archiver/Mac.tar",
        "archiver/Mac.tar.gz",
        "archiver/Mac.rar",
        "archiver/Mac.7z"
    ])
    def test_extract(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename), output_dir=".")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ['Mac.pdf']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename,rename_to", [
        ("archiver/Mac.zip", "Mäc.zip"),
        ("archiver/Mac.zip", "Mäc space Beth.zip"),
        ("archiver/Mac.zip", "Mäc foo , bar ! - áß.zip"),
        ("archiver/Mac.tar", "Mäc.tar"),
        ("archiver/Mac.tar.gz", "Mäc.tar.gz"),
        ("archiver/Mac.rar", "Mäc.rar"),
        ("archiver/Mac.7z", "Mäc.7z"),
    ])
    def test_extract_input_file_special_chars(self, capsys, filename, rename_to):
        assert os.listdir(os.getcwd()) == []
        shutil.copy(os.path.join(FIXTURE_DIR, filename), rename_to)
        if sys.version_info < (3, 0):  # py2
            pass  # not working
        else:  # py3+
            assert os.listdir(os.getcwd()) == [rename_to]
        instance = Extractor()
        res = instance.extract(archive_path=rename_to, output_dir=".")
        assert res is True
        assert instance.err is None
        assert len(os.listdir(os.getcwd())) == 2
        assert 'Mac.pdf' in os.listdir(os.getcwd())
        if sys.version_info < (3, 0):  # py2
            pass  # not working
        else:  # py3+
            assert rename_to in os.listdir(os.getcwd())

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.zip"])
    def test_extract_tmp(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename))
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == []
        assert os.listdir(instance.output_path) == ['Mac.pdf']
        assert os.path.dirname(instance.output_path).startswith("/tmp")
        shutil.rmtree(instance.output_path)

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.zip"])
    def test_extract_given_dir(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename), output_dir="./foobar")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ["foobar"]
        assert os.listdir(instance.output_path) == ['Mac.pdf']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", [
        "archiver/Mac.pw_infected.zip",
        "archiver/Mac.pw_infected.rar",
        "archiver/Mac.pw_infected.7z",
    ])
    def test_extract_password(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename), output_dir=".", password="infected")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ['Mac.pdf']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", [
        "archiver/Mac.pw_infected.zip",
        "archiver/Mac.pw_infected.rar",
        "archiver/Mac.pw_infected.7z",
    ])
    def test_extract_password_exclamation_fail(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename), output_dir=".", password="!_infected_!")
        assert res is False
        assert pytest.raises(subprocess.CalledProcessError)
        assert instance.err is not None
        assert os.listdir(os.getcwd()) == []

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", [
        "archiver/Mac.pw_infected.zip",
        "archiver/Mac.pw_infected.rar",
        "archiver/Mac.pw_infected.7z",
    ])
    def test_extract_password_umlaut_fail(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        # this requires from __future__ import unicode_literals on Python2 !
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename), output_dir=".", password="infäcted")
        assert res is False
        assert instance.err is not None
        assert os.listdir(os.getcwd()) == []

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.tbz2"])
    def test_specified_cls_name(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename), output_dir=".", cls_name="TarExtractor")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ['Mac.pdf']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.tbz2"])
    def test_specified_cls_name_does_not_exist(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename), output_dir=".", cls_name="ThisDoesNotExistExtractor")
        assert res is False
        assert instance.err is not None
        assert re.search("invalid Extractor", instance.err)
        assert os.listdir(os.getcwd()) == []

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac"])
    def test_file_without_extension(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename), output_dir=".")
        assert res is False
        assert instance.err is not None
        assert re.search("invalid archive_path", instance.err)
        assert os.listdir(os.getcwd()) == []

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", [
        "archiver/Mac.unknown",
    ])
    def test_file_with_unknown_extension(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Extractor()
        res = instance.extract(archive_path=os.path.join(FIXTURE_DIR, filename), output_dir=".")
        assert res is False
        assert instance.err is not None
        assert re.search("invalid archive_path", instance.err)
        assert os.listdir(os.getcwd()) == []


class TestCompressor:
    def test_init(self):
        instance = Compressor()
        assert isinstance(instance, Compressor)
        assert isinstance(instance.compressors_by_extension, dict)
        assert isinstance(instance.extensions, (list, KeysView))
        assert "zip" in instance.extensions

    @pytest.mark.usefixtures("cleandir")
    def test_file_path_list_item_does_not_exist(self, capsys):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path="/foobar2783987")
        assert res is False
        assert re.search("file does not exist", instance.err)
        assert os.listdir(os.getcwd()) == []

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_compress_to_tmp(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename))
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == []
        out_dir, out_file = os.path.split(instance.output_archive_path)
        assert out_file == 'export.zip'
        assert out_dir.startswith("/tmp")
        shutil.rmtree(out_dir)

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_compress(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ['export.zip']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_compress_new_dir(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./barfoo/")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ['barfoo']
        assert instance.output_archive_path == "./barfoo/export.zip"
        assert os.listdir(os.path.dirname(instance.output_archive_path)) == ['export.zip']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_specified_cls_name(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./", cls_name="ZipCompressor")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ['export.zip']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.tbz2"])
    def test_specified_cls_name_does_not_exist(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./", cls_name="ThisDoesNotExistCompressor")
        assert res is False
        assert instance.err is not None
        assert re.search("invalid Compressor.*ThisDoesNotExistCompressor", instance.err)
        assert os.listdir(os.getcwd()) == []

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_specified_cls_name_zip(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./", cls_name="ZipCompressor")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.path.dirname(instance.output_archive_path)) == ['export.zip']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_archive_no_extension(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./foo")
        assert res is False
        assert instance.err is not None
        assert re.search("unable to discover extension", instance.err)
        assert os.listdir(os.getcwd()) == []

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_archive_no_extension2(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./foo", cls_name="ZipCompressor")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ["foo.zip"]

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_specified_cls_name_7z(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./test.7z",
                                cls_name="SevenZipSystemCompressor")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ['test.7z']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_specified_cls_name_7z_pw(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./test_pw.7z",
                                cls_name="SevenZipSystemCompressor", password="infected")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ['test_pw.7z']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_specified_cls_name_7z_pw_dot(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./test.pw.7z",
                                cls_name="SevenZipSystemCompressor", password="infected")
        assert res is True
        assert instance.err is None
        assert os.listdir(os.getcwd()) == ['test.pw.7z']

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_specified_cls_name_pw_provided_but_not_supported(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./test.pw.7z",
                                cls_name="ZipCompressor", password="infected")
        assert res is False
        assert os.listdir(os.getcwd()) == []

    @pytest.mark.usefixtures("cleandir")
    @pytest.mark.parametrize("filename", ["archiver/Mac.pdf"])
    def test_file_without_extension(self, capsys, filename):
        assert os.listdir(os.getcwd()) == []
        instance = Compressor()
        res = instance.compress(file_path=os.path.join(FIXTURE_DIR, filename), archive_path="./test_compress")
        assert res is False
        assert instance.err is not None
        assert re.search("unable to discover extension", instance.err)
        assert os.listdir(os.getcwd()) == []
