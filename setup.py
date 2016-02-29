#!/usr/bin/env python
from setuptools import setup, find_packages

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

