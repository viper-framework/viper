#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.version import __version__

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
import pip

links = []
requires = []

requirement_files = ['requirements-base.txt']

for req_file in requirement_files:
    requirements = pip.req.parse_requirements(req_file, session=pip.download.PipSession())

    for item in requirements:
        # we want to handle package names and also repo urls
        if getattr(item, 'url', None):   # older pip has url
            links.append(str(item.url))
        if getattr(item, 'link', None):  # newer pip has link
            links.append(str(item.link))
        if item.req:
            requires.append(str(item.req))

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
    packages=find_packages(exclude=['tests', 'tests.*']),
    install_requires=requires,
    dependency_links=links,

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
