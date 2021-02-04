#TODO(alex): This closely mirrors config.py. It should be possible to modify config.py to suit both needs.

import os
import logging
import pkgutil
import viper
from os.path import expanduser
from configparser import ConfigParser

from viper.common.objects import Dictionary

log = logging.getLogger("viper")


class Mimetypes:
    def __init__(self):
        # Possible paths for the configuration file.
        # This should go in order from local to global.
        mime_paths = [
            os.path.join(os.path.dirname(viper.__file__), "data/mime.conf"),
            os.path.join(os.getcwd(), "mime.conf"),
            os.path.join(expanduser("~"), ".viper", "mime.conf"),
            "/etc/viper/mime.conf"
        ]

        # Try to identify the best location for the config file.
        self.mime_file = None
        for mime_path in mime_paths:
            if os.path.exists(mime_path):
                self.mime_file = mime_path
                break

        # If no config is available, we try to copy it either from the
        # package sample.
        if not self.mime_file:
            # If the local storage folder doesn"t exist, we create it.
            local_storage = os.path.join(expanduser("~"), ".viper")
            if not os.path.exists(local_storage):
                os.makedirs(local_storage)

            self.mime_file = os.path.join(local_storage, "mime.conf")
            mime_sample = pkgutil.get_data("viper", "data/mime.conf.sample")
            with open(self.mime_file, "wb") as handle:
                handle.write(mime_sample)

        
        # Parse the config file.
        mimes = self._mimes = ConfigParser(allow_no_value=True)
        mimes.read(self.mime_file)
        #print(mimes.sections())

        # Parse the config file and attribute for the current instantiated
        # object.
        for section in mimes.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in mimes.items(section):
                try:
                    if mimes.get(section, name) in ["0", "1"]:
                        raise ValueError

                    value = mimes.getboolean(section, name)
                except ValueError:
                    try:
                        value = mimes.getint(section, name)
                    except ValueError:
                        value = mimes.get(section, name)
                # Account for the new fields resulting from allow_no_value=True
                except:
                    value = None
                setattr(getattr(self, section), name, value)

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            log.warning("unable to fetch section: {}\n{}".format(section, e))
            print(e)

    def __getattr__(self, attr):
        log.warning("The section {} is missing in the config file.".format(attr))
        return None


__mimetypes__ = Mimetypes()

console_output = {}
console_output["filename"] = False