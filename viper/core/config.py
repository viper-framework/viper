# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
from os.path import expanduser
import shutil
try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

from viper.common.objects import Dictionary
from viper.common.constants import VIPER_ROOT


class Config:

    def __init__(self, cfg=None):
        # use cfg as a first priority
        if cfg:
            if os.path.exists(cfg):
                self.config_file = cfg
        else:
            # Possible paths for the configuration file.
            # This should go in order from local to global.
            config_paths = [
                os.path.join(os.getcwd(), 'viper.conf'),
                os.path.join(expanduser("~"), '.viper', 'viper.conf'),
                '/etc/viper/viper.conf'
            ]

            # Try to identify the best location for the config file.
            self.config_file = None
            for config_path in config_paths:
                if os.path.exists(config_path):
                    self.config_file = config_path
                    break

            # If no config is available, we try to copy it either from the
            # /usr/share/viper folder, or from VIPER_ROOT.
            if not self.config_file:
                share_viper = '/usr/share/viper/viper.conf.sample'

                cwd_viper = os.path.join(VIPER_ROOT, 'viper.conf.sample')

                # If the local storage folder doesn't exist, we create it.
                local_storage = os.path.join(expanduser("~"), '.viper')
                if not os.path.exists(local_storage):
                    os.makedirs(local_storage)

                self.config_file = os.path.join(local_storage, 'viper.conf')

                if os.path.exists(share_viper):
                    shutil.copy(share_viper, self.config_file)
                else:
                    shutil.copy(cwd_viper, self.config_file)

        # Parse the config file.
        config = ConfigParser()
        config.read(self.config_file)

        # Parse the config file and attribute for the current instantiated
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
            print(e)


console_output = {}
console_output['filename'] = False
