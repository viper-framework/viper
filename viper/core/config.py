# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import ConfigParser

from viper.common.out import *
from viper.common.objects import Dictionary

class Config:
    
    def __init__(self, file_name="viper", cfg=None):
    
        config = ConfigParser.ConfigParser()
        
        if cfg:
            test = config.read(cfg)
        else:
            test = config.read('viper.conf')
            
        # Check for empty config
        if len(test) == 0:
            print_error("Could not find a valid configuration file. Did you rename viper.conf.example to viper.conf")
            print_info("Trying to rename for you")
            try:
                os.rename('viper.conf.example', 'viper.conf')
                config.read('viper.conf')
            except:
                print_error("Failed to rename config file, Exiting")
                sys.exit()
            
        for section in config.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in config.items(section):
                try:
                    if config.get(section, name) in ["0", "1"]:
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
