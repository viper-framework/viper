# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
from os.path import expanduser
import logging
import shutil
try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

from viper.common.objects import Dictionary
from viper.common.constants import VIPER_ROOT

log = logging.getLogger('viper')


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
        config = self._config = ConfigParser()
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

    def parse_http_client(self, section=None):
        _proxies = None
        _verify = True
        _cert = None

        # when no http_client section is available provide defaults
        if self.get("http_client") is None:
            log.debug("No http_client section in config")
            setattr(self, "http_client", Dictionary())

        # check global config
        if self.http_client.https_proxy is None and self.http_client.no_proxy is None:
            log.debug("Global: Proxy not configured (using ENV or none)")
        else:
            if self.http_client.https_proxy:
                log.debug("Global: Proxy enabled: {} (no: {})".format(self.http_client.https_proxy,
                                                                      self.http_client.no_proxy))
                _proxies = {"http": self.http_client.https_proxy,
                            "https": self.http_client.https_proxy,
                            "no": self.http_client.no_proxy}
            else:
                log.debug("Global: Proxy disabled (overridden)")
                _proxies = {"http": "", "https": "", "no": None}

        if self.http_client.tls_verify is None:
            log.debug("Global: TLS verify not configured")
        else:
            if not self.http_client.tls_verify:
                log.debug("Global: TLS verify disabled")
                _verify = False
            else:
                log.debug("Global: TLS verify enabled")

        if _verify and self.http_client.tls_ca_bundle is not None:
            if self.http_client.tls_ca_bundle:
                log.debug("Global: Verify (CA_BUNDLE) set to: {}".format(self.http_client.tls_ca_bundle))
                _verify = self.http_client.tls_ca_bundle

        if self.http_client.tls_client_cert:
            log.debug("Global: Client certificate enabled: {}".format(self.http_client.tls_client_cert))
            _cert = self.http_client.tls_client_cert
        else:
            log.debug("Global: Client certificate not configured")

        self.http_client.proxies = _proxies
        self.http_client.verify = _verify
        self.http_client.cert = _cert

        if section:
            # check for module section and override global config if needed
            if section.https_proxy is None and section.no_proxy is None:
                if _proxies is None:
                    log.debug("Section: Proxy not configured (using ENV or none)")
                else:
                    log.debug("Section: Proxy not configured (using Global: {})".format(_proxies))
            else:
                if section.https_proxy:
                    log.debug("Section: Proxy enabled: {} (no: {})".format(section.https_proxy, section.no_proxy))
                    _proxies = {"http": section.https_proxy,
                                "https": section.https_proxy,
                                "no": section.no_proxy}
                else:
                    log.debug("Section: Proxy disabled (overridden)")
                    _proxies = {"http": "", "https": "", "no": None}

            if section.tls_verify is None:
                log.debug("Section: TLS verify not configured")
            else:
                if not section.tls_verify:
                    log.debug("Section: TLS verify disabled")
                    _verify = False
                else:
                    log.debug("Section: TLS verify enabled")
                    _verify = True

            if _verify and section.tls_ca_bundle is not None:
                if section.tls_ca_bundle:
                    log.debug("Section: Verify (CA_BUNDLE) set to: {}".format(section.tls_ca_bundle))
                    _verify = section.tls_ca_bundle

            if section.tls_client_cert:
                log.debug("Section: Client certificate enabled: {}".format(section.tls_client_cert))
                _cert = section.tls_client_cert
            else:
                log.debug("Section: Client certificate not configured")

            section.proxies = _proxies
            section.verify = _verify
            section.cert = _cert

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


__config__ = Config()

console_output = {}
console_output['filename'] = False
