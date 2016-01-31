#!/usr/bin/env python
import os
from setuptools import setup, find_packages

datafiles = [(root, [os.path.join(root, f) for f in files])
    for root, dirs, files in os.walk('data')]

setup(
    name='viper',
    version='1.3',
    author='Claudio Guarnieri',
    author_email='nex@nex.sx',
    description="Binary Analysis & Management Framework",
    url='http://viper.li',
    license='BSD 3-Clause',

    scripts=['viper-cli', 'viper-api', 'viper-web', 'viper-update'],
    packages=find_packages(),
)
