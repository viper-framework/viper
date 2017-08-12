# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import sys
import pytest

from viper.core.config import Config


class TestConfig:
    def test_init(self):
        instance = Config()
        assert isinstance(instance, Config)
        assert re.search("viper.conf", instance.config_file)

    def test_sample(self):
        instance = Config("viper.conf.sample")
        assert isinstance(instance, Config)
        assert instance.modules.store_output is True

    def test_sample_parse_global(self):
        instance = Config("viper.conf.sample")
        assert isinstance(instance, Config)

        instance.parse_http_client()
        assert instance.http_client.proxies is None
        assert instance.http_client.verify is True
        assert instance.http_client.cert is None

    def test_sample_parse_global_section(self):
        instance = Config("viper.conf.sample")
        assert isinstance(instance, Config)

        instance.parse_http_client(instance.cuckoo)

        assert instance.http_client.proxies is None
        assert instance.http_client.verify is True
        assert instance.http_client.cert is None

        assert instance.cuckoo.proxies is None
        assert instance.cuckoo.verify is True
        assert instance.cuckoo.cert is None

    def test_custom_parse_global(self):
        instance = Config("viper.conf.sample")
        assert isinstance(instance, Config)

        instance.http_client.https_proxy = "http://prx1.example.com:3128"
        instance.parse_http_client()

        assert instance.http_client.proxies is None
        assert instance.http_client.verify is True
        assert instance.http_client.cert is None

        # TODO (frennkie) Write some more parser logic validations here
