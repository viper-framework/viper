# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import shutil
import ConfigParser

from viper.common.out import *
from viper.common.objects import Dictionary

class Config:
    
    def __init__(self, file_name="viper", cfg=None):
        default_configuration_path = os.path.expanduser('~/.viper.conf')

        config = ConfigParser.ConfigParser()

        if cfg == None:
            cfg = default_configuration_path

        test = config.read(cfg)

        # Check for empty config
        if len(test) == 0:
            print_error("Could not find a valid configuration file. Did you copy viper.conf.sample to ~/.viper.conf?")
            print_info("Trying to create config for you")
            try:
                viper_installation_directory = os.path.dirname(os.path.realpath(__file__))
                sample_configuration_path = os.path.join(viper_installation_directory, '../../viper.conf.sample')

                shutil.copy(sample_configuration_path, default_configuration_path)

                config.read(default_configuration_path)
                default_repository_path = os.path.expanduser('~/Viper')

                print_info("Setting \"" + default_repository_path + "\" as your default repository...")
                config.set('paths', 'store_path', default_repository_path)
                config.write(open(default_configuration_path, "w"))

                print_info("Starting Viper")
            except:
                print_error("Failed to Create config file, Exiting")
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
