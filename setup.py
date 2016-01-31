from setuptools import setup, find_packages

setup(
    name='Viper',
    version='1.3',
    author='Claudio Guarnieri',
    author_email='nex@nex.sx',
    description="Binary Analysis & Management Framework",
    url='http://viper.li',
    license='BSD 3-Clause',

    scripts=['viper.py'],
    packages=find_packages(),
    package_data={'': ['data'], '': ['web']},
    include_package_data=True,
)
