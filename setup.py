#!/usr/bin/env python
from setuptools import setup, find_packages

with open('viper/common/version.py') as f:
    __version__ = ''
    exec(f.read())  # set __version__

setup(
    name='viper',
    version=__version__,
    author='Claudio Guarnieri',
    author_email='nex@nex.sx',
    description="Binary Analysis & Management Framework",
    url='http://viper.li',
    license='BSD 3-Clause',

    scripts=['viper-cli', 'viper-api', 'viper-web', 'viper-update'],
    packages=find_packages(),
)

