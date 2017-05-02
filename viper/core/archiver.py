# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import sys
import inspect
from distutils.spawn import find_executable
import pkg_resources
import logging

# Compression
import tarfile
import zipfile
import gzip
import bz2

import tempfile
import shutil

import subprocess

log = logging.getLogger('viper')


class Archiver(object):
    """Archiver Class"""

    title = None
    min_python_version = (2, 7)
    dependency_list_python = []
    dependency_list_system = []
    supports_extensions = []
    supports_password = False

    @property
    def cls_name(self):
        return self.__class__.__name__

    @property
    def summary(self):
        return {"cls_name": self.cls_name,
                "title": self.title,
                "extensions": self.supports_extensions,
                "password": self.supports_password}

    def _is_subclass(self, obj):
        return inspect.isclass(obj) and issubclass(obj, self.__class__)

    def get_subclasses(self):
        """Yields all subclasses of this class"""
        for name, obj in inspect.getmembers(sys.modules[__name__], predicate=self._is_subclass):
            if hasattr(obj, "__bases__") and self.__class__ in obj.__bases__:
                yield obj

    def check(self):
        min_python_version = self._check_min_python_version()
        dep_python = self._check_dependencies_python()
        dep_system = self._check_dependencies_system()
        if min_python_version and dep_python and dep_system:
            return True
        else:
            return False

    def _check_min_python_version(self):
        if sys.version_info >= self.min_python_version:
            log.debug("{}: Python Version ok".format(self.__class__.__name__))
            return True
        else:
            log.warning("{}: Python Version NOT ok".format(self.__class__.__name__))
            return False

    def _check_dependencies_python(self):
        if not self.dependency_list_python:
            return True

        missing = []

        for item in self.dependency_list_python:
            try:
                pkg_resources.require(item)
            except pkg_resources.DistributionNotFound as err:
                log.debug("{}: Missing Python dependency: {}".format(self.__class__.__name__, err))
                missing.append(item)
            except pkg_resources.VersionConflict as err:
                log.debug("{}: Python dependency wrong version: {}".format(self.__class__.__name__, err))
                missing.append(item)

        if missing:
            log.warning("{}: Missing/Failed Python dependencies: {}".format(self.__class__.__name__, missing))
            return False

        return True

    def _check_dependencies_system(self):
        if not self.dependency_list_system:
            return True

        missing = [item for item in self.dependency_list_system if not find_executable(item)]

        if missing:
            log.warning("{}: Missing System dependencies: {}".format(self.__class__.__name__, missing))
            return False
        else:
            return True

    @staticmethod
    def _splitext(file_name):
        for ext in ['.tar.gz', '.tar.bz2']:
            if file_name.endswith(ext):
                return file_name[:-len(ext)], file_name[-len(ext):]
        return os.path.splitext(file_name)

    def auto_discover_ext(self, file_path):
        """discover the extension (to get type of extraction/compression) from file name"""
        name, ext = self._splitext(os.path.basename(file_path))
        return name, ext.lstrip(".")


# Generic Extractor class
class Extractor(Archiver):
    """Extractor class"""

    # auto generated dict that maps extensions to subclass implementations
    extractors = {}
    extractors_by_extension = {}

    err = None

    def __init__(self, *args, **kwargs):
        super(Extractor, self).__init__()

        # path of file to extract or file/dir to compress
        self._input_path = None
        # path of file or directory to extract to or where to stored compressed archive
        self._output_path = None

        self.get_supported_extensions()

    def get_supported_extensions(self):
        for item in self.get_subclasses():
            instance = item()
            if instance.check():
                for ext in instance.supports_extensions:
                    self.extractors.update({instance.cls_name: instance})
                    try:
                        self.extractors_by_extension[ext].append(instance)
                    except KeyError:
                        self.extractors_by_extension[ext] = [instance]

    @property
    def extensions(self):
        return self.extractors_by_extension.keys()

    @property
    def input_path(self):
        return self._input_path

    @input_path.setter
    def input_path(self, value):
        self._input_path = value

    @property
    def output_path(self):
        return self._output_path

    @output_path.setter
    def output_path(self, value):
        self._output_path = value

    def extract(self, archive_path, output_dir=None, cls_name=None, password=None, **kwargs):
        """Method for extracting an archive file (e.g. zip, tar, tar.gz, 7z)

        :param archive_path: absolute path to file to extract
        :type archive_path: str
        :param output_dir: **optional** absolute path to directory to extract to
        :type output_dir: str
        :param cls_name: name of Extractor/Compressor class to use
        :type cls_name: str
        :param password: **optional** password to use
        :type password: str
        :param kwargs: keyword arguments (e.g for special flags)
        :returns True if successful, otherwise False

        """

        if not os.path.isfile(archive_path):
            self.err = "invalid archive_path (file does not exist): {}".format(archive_path)
            log.error(self.err)
            return False

        if output_dir:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                log.debug("creating output directory: {}".format(output_dir))
        else:
            output_dir = tempfile.mkdtemp(prefix="viper_tmp_")
            log.debug("created output directory: {}".format(output_dir))

        if cls_name:
            log.debug("Extractor specified by caller")
            try:
                sub = self.extractors[cls_name]
            except KeyError:
                self.err = "invalid Extractor: {}. Check for missing dependencies.".format(cls_name)
                log.error(self.err)
                return False

        else:
            _, ext = self.auto_discover_ext(archive_path)
            if not ext:
                self.err = "unable to discover extension"
                log.error(self.err)
                return False

            try:
                sub = self.extractors_by_extension[ext][0]  # default to first
                if password:  # try to find one that supports pw
                    for item in self.extractors_by_extension[ext]:
                        if item.supports_password:
                            sub = item
                            break
                        else:
                            sub = self.extractors_by_extension[ext][0]  # try first anyway

            except KeyError:
                self.err = "no available Extractor supports extension: {}. Check for missing dependencies.".format(cls_name)
                log.error(self.err)
                return False

        sub.input_path = archive_path
        sub.output_path = output_dir

        if sub.supports_password:
            ret = sub.run(password=password, **kwargs)
        else:
            ret = sub.run(**kwargs)

        if ret:
            self.output_path = sub.output_path
            log.debug(self.output_path)
            return True
        else:
            self.err = sub.err
            log.error(self.err)
            return False


# Extractor implementations
class ZipExtractor(Extractor):
    """Zip"""

    title = "Zip"
    supports_extensions = ["zip"]
    supports_password = True

    def run(self, password=None, **kwargs):
        log.info("Extract: {}".format(self.title))

        if password:
            try:
                password = password.encode('ascii')  # py3 requires bytes (not str)
            except UnicodeEncodeError as err:
                log.error("Extract ({}) failed. Password only supports ascii characters: {}".format(self.title, err))
                self.err = err
                return False

        try:
            with zipfile.ZipFile(self.input_path) as zf:
                zf.extractall(self.output_path, pwd=password)

        except Exception as err:
            log.error("Extract ({}) failed. Error: {}".format(self.title, err))
            if "password" in err.__repr__():
                log.warning("Password either missing or incorrect!")
            self.err = err
            return False

        return True


class GZipExtractor(Extractor):
    """GZip"""

    title = "GZip"
    supports_extensions = ["gz"]

    # need to override output_path setter as we want to tell GZip to which file to extract to (instead of a directory)
    @property
    def output_path(self):
        return self._output_path

    @output_path.setter
    def output_path(self, value):
        base_name, _ = os.path.splitext(os.path.basename(self.input_path))
        self._output_path = os.path.join(value, base_name)

    def run(self, **kwargs):
        log.info("Extract: {}".format(self.title))

        try:
            with gzip.GzipFile(self.input_path, 'rb') as zf:
                decompressed = zf.read()

            with open(self.output_path, "wb") as df:
                df.write(decompressed)

        except Exception as err:
            log.error("Extract ({}) failed. Error: {}".format(self.title, err))
            self.err = err
            return False

        return True


class BZ2Extractor(Extractor):
    """BZip2"""

    title = "BZip2"
    supports_extensions = ["bz2"]

    # need to override output_path setter as we want to tell BZip2 to which file to extract to (instead of a directory)
    @property
    def output_path(self):
        return self._output_path

    @output_path.setter
    def output_path(self, value):
        base_name, _ = os.path.splitext(os.path.basename(self.input_path))
        self._output_path = os.path.join(value, base_name)

    def run(self, **kwargs):
        log.info("Extract: {}".format(self.title))

        try:
            with bz2.BZ2File(self.input_path, 'rb') as zf:
                decompressed = zf.read()

            with open(self.output_path, "wb") as df:
                df.write(decompressed)

        except Exception as err:
            log.error("Extract ({}) failed. Error: {}".format(self.title, err))
            self.err = err
            return False

        return True


class TarExtractor(Extractor):
    """Tar"""

    title = "Tar"
    supports_extensions = ["tar", "tar.gz", "tar.bz2"]

    def run(self, **kwargs):
        log.info("Extract: {} (or tar.gz/tar.bz2)".format(self.title))

        if not tarfile.is_tarfile(self.input_path):
            self.err = "This is not a tar file"
            log.error(self.err)
            return False

        try:
            with tarfile.open(self.input_path, 'r:*') as tarf:
                tarf.extractall(self.output_path)

        except Exception as err:
            log.error("Extract ({}) failed. Error: {}".format(self.title, err))
            self.err = err
            return False

        return True


class RarExtractor(Extractor):
    """RAR"""

    title = "Rar"
    dependency_list_python = ["rarfile"]
    dependency_list_system = ["unrar"]
    supports_extensions = ["rar"]
    supports_password = True

    def run(self, password=None, **kwargs):
        log.info("Extract: {}".format(self.title))
        import rarfile

        try:
            with rarfile.RarFile(self.input_path) as rf:
                rf.extractall(self.output_path, pwd=password)

        except Exception as err:
            log.error("Extract ({}) failed. Error: {}".format(self.title, err))
            self.err = err
            return False

        return True


class SevenZipSystemExtractor(Extractor):
    """7-Zip"""

    title = "7-Zip (System)"
    dependency_list_system = ["7z"]
    supports_extensions = ["7z"]
    supports_password = True

    def run(self, password=None, **kwargs):
        log.info("Extract: {}".format(self.title))

        tmp_dir = tempfile.mkdtemp(prefix="viper_tmp_")

        try:
            out = "-o{}".format(tmp_dir)
            if password:
                pwd = "-p{}".format(password)
                subprocess.check_output(["7z", "x", out, "-r", "-y", pwd, self.input_path], stderr=subprocess.STDOUT)
            else:
                subprocess.check_output(["7z", "x", out, "-r", "-y", self.input_path], stderr=subprocess.STDOUT)

            for item in os.listdir(tmp_dir):
                shutil.move(os.path.join(tmp_dir, item), self.output_path)

        except subprocess.CalledProcessError as err:
            log.error("Running shell command \"{}\" caused error: {} (RC: {}".format(err.cmd, err.output, err.returncode))
            self.err = err

            lines = err.output.decode("utf-8")
            for line in lines.split("\n"):
                if re.search("password", line.lower()):
                    log.warning("Password either missing or incorrect!")

            return False

        except Exception as err:
            log.error("Extract ({}) failed. Error: {}".format(self.title, err))
            self.err = err
            return False

        finally:
            shutil.rmtree(tmp_dir)

        return True


# Generic Compressor class
class Compressor(Archiver):
    """Compressor class"""

    # auto generated dict that maps extensions to subclass implementations
    compressors = {}
    compressors_by_extension = {}

    err = None

    def __init__(self, *args, **kwargs):
        super(Compressor, self).__init__()

        # default basename for compressed files
        self.default_basename = "export"
        # default extension
        self.default_ext = "zip"

        # list of tuples each containing:
        # * 1) path to file or directory to compress
        # * 2) name of the compressed file in the archive
        self._input_tuple_list = None

        # path where to store compressed archive (full path - e.g. /tmp/files/sample.zip)
        self._output_archive_path = None
        # name compressed archive (name only - e.g. sample.zip)
        self._output_archive_name = None
        # basename of archive (name only - e.g. sample)
        self._output_archive_basename = None
        # extension of archive (name only - e.g. zip)
        self._output_archive_ext = None

        self.get_supported_extensions()

    def get_supported_extensions(self):
        for item in self.get_subclasses():
            instance = item()
            if instance.check():
                for ext in instance.supports_extensions:
                    self.compressors.update({instance.cls_name: instance})
                    try:
                        self.compressors_by_extension[ext].append(instance)
                    except KeyError:
                        self.compressors_by_extension[ext] = [instance]

    @property
    def extensions(self):
        return self.compressors_by_extension.keys()

    @property
    def input_tuple_list(self):
        return self._input_tuple_list

    @input_tuple_list.setter
    def input_tuple_list(self, value):
        self._input_tuple_list = value

    @property
    def output_archive_path(self):
        return self._output_archive_path

    @output_archive_path.setter
    def output_archive_path(self, value):
        self._output_archive_path = value

    @property
    def output_archive_name(self):
        return self._output_archive_name

    @output_archive_name.setter
    def output_archive_name(self, value):
        self._output_archive_name = value

    @property
    def output_archive_basename(self):
        return self._output_archive_basename

    @output_archive_basename.setter
    def output_archive_basename(self, value):
        self._output_archive_basename = value

    @property
    def output_archive_ext(self):
        return self._output_archive_ext

    @output_archive_ext.setter
    def output_archive_ext(self, value):
        self._output_archive_ext = value

    def compress(self, file_path, file_name=None, archive_path=None, cls_name=None, password=None, **kwargs):
        """compress one file into an archive (e.g. zip, tar, tar.gz, 7z)

        :param file_path: path to file to compress
        :type file_path: str
        :param file_name: name of file in archive (defaults to retrieving name from file_path)
        :type file_name: str
        :param archive_path: **optional** full path to archive (e.g. "/tmp/sample51.zip")
        :type archive_path: str
        :param cls_name: **optional** name of Compressor class to use
        :type cls_name: str
        :param password: **optional** password to use
        :type password: str
        :param kwargs: keyword arguments (e.g for special flags)
        :returns True if successful, otherwise False

        """

        if not os.path.isfile(file_path):
            self.err = "invalid file_path (file does not exist): {}".format(file_path)
            log.error(self.err)
            return False

        if not file_name:
            _, file_name = os.path.split(file_path)

        archive_basename = None
        archive_ext = self.default_ext  # if no other extension can be determined then default to zip

        if not archive_path:
            archive_dir = tempfile.mkdtemp(prefix="viper_tmp_")
            log.debug("created output directory: {}".format(archive_dir))
        else:
            archive_dir, archive_name = os.path.split(archive_path)
            if archive_name:
                archive_basename, archive_ext = self.auto_discover_ext(archive_name)

            if not os.path.exists(archive_dir):
                os.makedirs(archive_dir)
                log.debug("created output directory: {}".format(archive_dir))

        if cls_name:  # try to get specified sub class by provided name
            log.debug("Compressor specified by caller")
            try:
                sub = self.compressors[cls_name]
            except KeyError:
                self.err = "invalid Compressor: {} (check for missing dependencies)".format(cls_name)
                log.error(self.err)
                return False

            if not archive_path:
                archive_ext = sub.supports_extensions[0]

        else:
            # class not provided - try to determine class by file extension
            if archive_basename:
                _, _res_auto_discover_ext = self.auto_discover_ext(archive_basename)
                if not _res_auto_discover_ext:
                    self.err = "unable to discover extension"
                    log.error(self.err)
                    return False
                else:
                    archive_ext = _res_auto_discover_ext

            try:
                sub = self.compressors_by_extension[archive_ext][0]  # default to first
                if password:  # try to find one that supports pw
                    for item in self.compressors_by_extension[archive_ext]:
                        if item.supports_password:
                            sub = item
                            break
                        else:
                            sub = self.compressors_by_extension[archive_ext][0]  # try first anyway

            except KeyError:
                self.err = "no available Extractor supports extension: {} (check for missing dependencies)".format(cls_name)
                log.error(self.err)
                return False

        if not archive_basename:
            archive_basename = self.default_basename

        if archive_ext:
            if archive_ext in sub.supports_extensions:  # e.g. for ZipCompressor file.zip stays file.zip
                archive_name = "{}.{}".format(archive_basename, archive_ext)
            else:   # e.g. file.exe will become file.exe.zip
                archive_name = "{}.{}.{}".format(archive_basename, archive_ext, sub.supports_extensions[0])
        else:  # e.g. file will become file.zip
            archive_name = "{}.{}".format(archive_basename, sub.supports_extensions[0])

        output_path = os.path.join(archive_dir, archive_name)

        if os.path.isfile(output_path):
            self.err = "file exists - will not overwrite: {}".format(output_path)
            log.error(self.err)
            return False

        sub.input_tuple_list = [(file_path, file_name)]

        sub.output_archive_path = output_path
        sub.output_archive_name = archive_name
        sub.output_archive_basename, sub.output_archive_ext = self.auto_discover_ext(archive_name)

        if password and not sub.supports_password:
            self.err = "password provided but modules does not support encryption: {}".format(sub.cls_name)
            log.error(self.err)
            return False

        if sub.supports_password:
            ret = sub.run(password=password, **kwargs)
        else:
            ret = sub.run(**kwargs)

        if ret:
            self.output_archive_path = sub.output_archive_path
            log.info(self.output_archive_path)
            return True
        else:
            self.err = sub.err
            log.error(self.err)
            return False

# All Compressor implementations MUST take a list of tuples as input.
# The list represents multiple files that MUST be compressed into one archive.
# The tuples specify for each file the path on disk to a file and the path
# that this file MUST have in the archive.
# The path of the compressed files within the archive MUST be prepended by
# basename of the archive.
#
# Example:
#   Archive name is: sample.zip
#
#   self.output_archive_path is /tmp/exports/sample.zip
#   self.input_tuple_list = [("/tmp/eggs", "eggs"), ("/tmp/spam/foo.txt", "foobar/spam_foo.txt")]
#
#   The resulting archive MUST - when extracted - generate two files (relative to local dir):
#   * ./sample/eggs
#   * ./sample/foobar/spam_foo.txt
#
# Reminder: Do not leave behind artifacts (e.g. temporary files or directories)


# Compressor implementations
class ZipCompressor(Compressor):
    """Zip"""

    title = "Zip"
    supports_extensions = ["zip"]

    def run(self, **kwargs):
        log.info("Compress: {}".format(self.title))

        try:
            with zipfile.ZipFile(self.output_archive_path, 'w') as zf:
                for item_path, item_name in self.input_tuple_list:
                    zf.write(item_path, arcname=os.path.join(self.output_archive_basename, item_name))

        except Exception as err:
            log.error("Compress ({}) failed. Error: {}".format(self.title, err))
            self.err = err
            return False

        return True


class SevenZipSystemCompressor(Compressor):
    """7-Zip"""

    title = "7-Zip (System)"
    dependency_list_system = ["7z"]
    supports_extensions = ["7z"]
    supports_password = True

    def run(self, password=None, **kwargs):
        log.info("Compress: {}".format(self.title))

        tmp_dir = tempfile.mkdtemp(prefix="viper_tmp_")
        archive_sub_dir = os.path.join(tmp_dir, self.output_archive_basename)
        os.mkdir(archive_sub_dir)

        for item_path, item_name in self.input_tuple_list:
            shutil.copyfile(item_path, os.path.join(archive_sub_dir, item_name))

        try:
            if password:
                pwd = "-p{}".format(password)
                res = subprocess.check_output(["7z", "a", pwd, "-y", self.output_archive_path, "-w", archive_sub_dir], stderr=subprocess.STDOUT)
            else:
                res = subprocess.check_output(["7z", "a", "-y", self.output_archive_path, "-w", archive_sub_dir], stderr=subprocess.STDOUT)
            log.debug("Result: {}".format(res))

        except subprocess.CalledProcessError as err:
            log.debug("Running shell command \"{}\" caused error: {} (RC: {}".format(err.cmd, err.output, err.returncode))
            self.err = err
            os.remove(self.output_archive_path)
            return False

        except Exception as err:
            log.error("Compress ({}) failed. Error: {}".format(self.title, err))
            self.err = err
            return False

        finally:
            # this also runs if an Exception occurs: make sure that temp dir is deleted
            shutil.rmtree(tmp_dir)

        return True
