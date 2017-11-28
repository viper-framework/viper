# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import re

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

    def test_missing_section_http_client(self):
        instance = Config("viper.conf.sample")
        assert hasattr(instance, "http_client")

        delattr(instance, "http_client")
        assert instance.http_client is None

        instance.parse_http_client()
        assert hasattr(instance, "http_client")

    def test_sample_parse_global(self):
        instance = Config("viper.conf.sample")

        instance.parse_http_client()
        assert instance.http_client.proxies is None
        assert instance.http_client.verify is True
        assert instance.http_client.cert is None

    def test_sample_parse_global_section(self):
        instance = Config("viper.conf.sample")

        instance.parse_http_client(instance.cuckoo)

        assert instance.http_client.proxies is None
        assert instance.http_client.verify is True
        assert instance.http_client.cert is None

        assert instance.cuckoo.proxies is None
        assert instance.cuckoo.verify is True
        assert instance.cuckoo.cert is None

    def test_custom_parse_global(self):
        instance = Config("viper.conf.sample")

        # http_proxy, no_proxy
        instance.http_client.https_proxy = None
        instance.parse_http_client()
        assert instance.http_client.proxies is None

        instance.http_client.https_proxy = False
        instance.parse_http_client()
        assert instance.http_client.proxies == {'http': '', 'https': '', 'no': None}

        instance.http_client.https_proxy = "http://prx1.example.com:3128"
        instance.parse_http_client()
        assert instance.http_client.proxies == {'http': 'http://prx1.example.com:3128', 'https': 'http://prx1.example.com:3128', 'no': None}

        # tls_verify
        instance.http_client.tls_verify = None
        instance.parse_http_client()
        assert instance.http_client.verify is True

        instance.http_client.tls_verify = True
        instance.parse_http_client()
        assert instance.http_client.verify is True

        instance.http_client.tls_verify = False
        instance.parse_http_client()
        assert instance.http_client.verify is False

        # tls_ca_bundle
        instance.http_client.tls_verify = True
        instance.http_client.tls_ca_bundle = "/etc/ssl/certs/ca_bundle.crt"
        instance.parse_http_client()
        assert instance.http_client.verify == "/etc/ssl/certs/ca_bundle.crt"

        # tls_client_cert
        instance.http_client.tls_client_cert = None
        instance.parse_http_client()
        assert instance.http_client.cert is None

        instance.http_client.tls_client_cert = "client.pem"
        instance.parse_http_client()
        assert instance.http_client.cert == "client.pem"

        # TODO (frennkie) Write some more parser logic validations here
    def test_custom_parse_global_section(self):
        instance = Config("viper.conf.sample")

        # http_proxy, no_proxy
        instance.http_client.https_proxy = None
        instance.koodous.https_proxy = None
        instance.parse_http_client(section=instance.koodous)
        assert instance.koodous.proxies is None

        instance.http_client.https_proxy = "http://prx1.example.com:3128"
        instance.koodous.https_proxy = None
        instance.parse_http_client(section=instance.koodous)
        assert instance.koodous.proxies == {'http': 'http://prx1.example.com:3128', 'https': 'http://prx1.example.com:3128', 'no': None}

        instance.http_client.https_proxy = "http://prx1.example.com:3128"
        instance.koodous.https_proxy = False
        instance.parse_http_client(section=instance.koodous)
        assert instance.koodous.proxies == {'http': '', 'https': '', 'no': None}

        instance.http_client.https_proxy = "http://prx1.example.com:3128"
        instance.koodous.https_proxy = "http://prx2.example.com:8080"
        instance.parse_http_client(section=instance.koodous)
        assert instance.koodous.proxies == {'http': 'http://prx2.example.com:8080', 'https': 'http://prx2.example.com:8080', 'no': None}

        # tls_verify
        instance.parse_http_client(section=instance.koodous)
        assert instance.koodous.verify is True

        instance.koodous.tls_verify = False
        instance.parse_http_client(section=instance.koodous)
        assert instance.koodous.verify is False

        instance.koodous.tls_verify = True
        instance.parse_http_client(section=instance.koodous)
        assert instance.koodous.verify is True

        # tls_ca_bundle
        instance.koodous.tls_verify = True
        instance.koodous.tls_ca_bundle = "/etc/ssl/certs/ca_bundle2.crt"
        instance.parse_http_client(section=instance.koodous)
        assert instance.koodous.verify == "/etc/ssl/certs/ca_bundle2.crt"

        # tls_client_cert
        instance.koodous.tls_client_cert = "client_koodous.pem"
        instance.parse_http_client(section=instance.koodous)
        assert instance.koodous.cert == "client_koodous.pem"
