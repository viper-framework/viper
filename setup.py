#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import pip
import glob
from setuptools import setup

from viper.common.version import __version__
from viper.common.constants import DIST_DIR_YARA_RULES, DIST_DIR_PEID

REQUIREMENT_FILES = ['requirements-base.txt', "requirements-modules.txt", "requirements-web.txt"]


def get_packages(package):
    """
    Return root package and all sub-packages.
    """
    return [dirpath
            for dirpath, dirnames, filenames in os.walk(package)
            if os.path.exists(os.path.join(dirpath, '__init__.py'))]


def get_package_data(package):
    """
    Return all files under the root package, that are not in a
    package themselves.
    """
    walk = [(dirpath.replace(package + os.sep, '', 1), filenames)
            for dirpath, dirnames, filenames in os.walk(package)
            if not os.path.exists(os.path.join(dirpath, '__init__.py'))]

    filepaths = []
    for base, filenames in walk:
        filepaths.extend([os.path.join(base, filename)
                          for filename in filenames])
    return {package: filepaths}


def get_requirements(req_files):
    """
    Collect requirements for `install_requires` setting
    """
    links = []
    requires = []
    for req_file in req_files:
        requirements = pip.req.parse_requirements(req_file, session=pip.download.PipSession())

        for item in requirements:
            # we want to handle package names and also repo urls
            if getattr(item, 'url', None):   # older pip has url
                if str(item.url).startswith("git+https://github.com"):
                    links.append(str(item.url))
                    continue
            if getattr(item, 'link', None):  # newer pip has link
                if str(item.link).startswith("git+https://github.com"):
                    links.append(str(item.link))
                    continue
            if item.req:  # only record req if neither url nor link is present
                requires.append(str(item.req))
    return requires, links


requires, links = get_requirements(REQUIREMENT_FILES)

# TODO(frennkie) Evil Hack!
print("===================================================")
print("Starting installation of dependencies from Github..")
print("===================================================")
for idx, link in enumerate(links, 1):
    print("{} - Source: {}".format(idx, link))
    pip.main(['install', link])

for idx, url in enumerate(links, 1):
    print("{} - Source: {}".format(idx, url))
    pip.main(['install', url])


description = "Binary Analysis & Management Framework"

setup(
    name='viper',
    version=__version__,
    author='Claudio Guarnieri',
    author_email='nex@nex.sx',
    description=description,
    long_description=description,
    url='http://viper.li',

    platforms='any',
    scripts=['viper-cli', 'viper-api', 'viper-web', 'viper-update'],

    packages=get_packages('viper'),
    package_data=get_package_data('viper'),
    install_requires=requires,
    # dependency_links=links,  # broken - using "Evil Hack!" as workaround

    data_files=[('/', ['viper.conf.sample']),
                ('/' + DIST_DIR_PEID, glob.glob("data/peid/*")),
                ('/' + DIST_DIR_YARA_RULES, glob.glob("data/yara/*"))],
    zip_safe=False,

    tests_require=['pytest'],

    # BSD 3-Clause License:
    # - http://choosealicense.com/licenses/bsd-3-clause
    # - http://opensource.org/licenses/BSD-3-Clause
    license='BSD 3-Clause',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Topic :: Security',

        'License :: OSI Approved :: BSD License',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',

        'Operating System :: POSIX :: Linux',
    ],

    keywords='binary analysis management malware research',
)
