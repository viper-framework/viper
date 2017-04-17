# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
from tests.conftest import FIXTURE_DIR
from viper.common.objects import MispEvent
import pytest


class TestObjects:

    @pytest.mark.parametrize("filename", ["58e902cd-dae8-49b9-882b-186c02de0b81.json"])
    def test_mispevent(self, capsys, filename):
        mispevent = MispEvent(os.path.join(FIXTURE_DIR, filename))
        mispevent.online()
        mispevent.offline()
        ips = mispevent.get_all_ips()
        domains = mispevent.get_all_domains()
        urls = mispevent.get_all_urls()
        hashes = mispevent.get_all_hashes()
        assert '191.101.230.149' in ips
        assert not domains
        assert not urls
        assert '722050c1b3f110c0ac9f80bc80723407' in hashes[0]
        assert not hashes[1]
