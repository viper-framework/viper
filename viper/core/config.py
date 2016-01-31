# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import shutil
import ConfigParser

from viper.common.out import *
from viper.common.objects import Dictionary

class Config:
    
    def __init__(self, cfg=None):
        # Possible paths for the configuration file.
        # This should go in order from local to global.
        config_paths = [
            os.path.join(os.getcwd(), 'viper.conf'),
            os.path.join(os.getenv('HOME'), '.viper', 'viper.conf'),
            '/etc/viper/viper.conf'
        ]

        # Try to identify the best location for the config file.
        config_file = None
        for config_path in config_paths:
            if os.path.exists(config_path):
                config_file = config_path
                break

        # If no config file is available, we should exit.
        if not config_file:
            print("Unable to find any config file!")
            # TODO: this is temporary. Need to fix in order to better support
            # the process of making a global installation of Viper.
            shutil.copy('viper.conf.sample', 'viper.conf')
        
        # Pasre the config file.
        config = ConfigParser.ConfigParser()
        config.read(config_file)

        # Pars ethe config file and attribute for the current instantiated
        # object.
        for section in config.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in config.items(section):
                try:
                    if config.get(section, name) in ['0', '1']:
                        raise ValueError

                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                setattr(getattr(self, section), name, value)

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            print e
