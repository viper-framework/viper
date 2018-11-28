# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import sys

import pytest
from tests.conftest import FIXTURE_DIR

from viper.core.session import __sessions__
from viper.core.config import __config__


from viper.modules import misp
from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

try:
    from .keys import url, apikey, vt_key
    live_tests = True
except ImportError:
    live_tests = False


class TestMISP:
    def test_init(self):
        instance = misp.MISP()
        assert isinstance(instance, misp.MISP)
        assert isinstance(instance, Module)

    def test_args_exception(self):
        instance = misp.MISP()
        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*Upload and query IOCs to/from a MISP instance*")

    def test_run_help(self, capsys):
        instance = misp.MISP()
        instance.set_commandline(["--help"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_short_help(self, capsys):
        instance = misp.MISP()
        instance.set_commandline(["-h"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_invalid_option(self, capsys):
        instance = misp.MISP()
        instance.set_commandline(["invalid"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*argument subname: invalid choice: 'invalid'.*", out)

    def test_tag_list(self, capsys):
        instance = misp.MISP()
        instance.command_line = ['--off', 'tag', '--list']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*CIRCL Taxonomy.*", out)

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="Encoding foobar, don't care.")
    def test_tag_search(self, capsys):
        instance = misp.MISP()
        instance.command_line = ['--off', 'tag', '-s', 'ciRcl']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*circl:incident-classification=\"system-compromise\".*", out)

    def test_tag_details(self, capsys):
        instance = misp.MISP()
        instance.command_line = ['--off', 'tag', '-d', 'circl']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Denial of Service | denial-of-service.*", out)

    def test_galaxies_list(self, capsys):
        instance = misp.MISP()
        instance.command_line = ['--off', 'galaxies', '--list']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*microsoft-activity-group.*", out)

    def test_galaxies_search(self, capsys):
        instance = misp.MISP()
        instance.command_line = ['--off', 'galaxies', '--search', 'foo']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Foozer.*", out)

    def test_galaxies_list_cluster(self, capsys):
        instance = misp.MISP()
        instance.command_line = ['--off', 'galaxies', '-d', 'rat']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*BlackNix.*", out)

    def test_galaxies_list_cluster_value(self, capsys):
        instance = misp.MISP()
        instance.command_line = ['--off', 'galaxies', '-d', 'rat', '-v', 'BlackNix']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*leakforums.net.*", out)

    # Live tests - require a MISP instance.
    @pytest.mark.skipif(not live_tests, reason="No API key provided")
    def test_create_event(self, capsys):
        instance = misp.MISP()
        instance.command_line = ['--url', url, '-k', apikey, '-v', 'create_event', '-i', 'Viper test event']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Session opened on MISP event.*", out)
        event_id = re.findall(r".*Session opened on MISP event (.*)\..*", out)[0]

        instance.command_line = ['--url', url, '-k', apikey, '-v', 'add', 'ip-dst', '8.8.8.8']
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(rf".*Session on MISP event {event_id} refreshed.*", out)

        instance.command_line = ['--url', url, '-k', apikey, '-v', 'show']
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*ip-dst | 8.8.8.8.*", out)

        __sessions__.new(os.path.join(FIXTURE_DIR, 'chromeinstall-8u31.exe'))

        instance.command_line = ['add_hashes']
        instance.run()
        instance.command_line = ['--url', url, '-k', apikey, '-v', 'show']
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(rf".*Session on MISP event {event_id} refreshed.*", out)

    # Live tests - require a MISP instance.
    @pytest.mark.skipif(not live_tests, reason="No API key provided")
    def test_check_hashes(self, capsys):
        instance = misp.MISP()
        instance.command_line = ['--url', url, '-k', apikey, '-v', 'create_event', '-i', 'Viper test event - check hashes']

        instance.run()
        out, err = capsys.readouterr()

        assert re.search(r".*Session opened on MISP event.*", out)
        event_id = re.findall(r".*Session opened on MISP event (.*)\..*", out)[0]

        instance.command_line = ['--url', url, '-k', apikey, '-v', 'add', 'sha1', 'afeee8b4acff87bc469a6f0364a81ae5d60a2add']
        instance.run()
        out, err = capsys.readouterr()

        assert re.search(rf".*Session on MISP event {event_id} refreshed.*", out)

        __config__.virustotal.virustotal_key = vt_key

        instance.command_line = ['--url', url, '-k', apikey, 'check_hashes', '-p']
        instance.run()
        out, err = capsys.readouterr()
        # print(out, err)
        assert re.search(r".*Sample available in VT.*", out)
