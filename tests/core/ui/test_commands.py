# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import re
import os
import sys

try:
    from unittest import mock
except ImportError:
    # Python2
    import mock

from viper.core.plugins import load_commands
from viper.core.database import Database
from viper.core.project import Project
from viper.core.session import __sessions__
from tests.conftest import FIXTURE_DIR


class TestCommands:
    cmd = load_commands()

    def setup_class(cls):
        cmd = load_commands()
        cmd['open']['obj']('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        cmd['store']['obj']()

    def teardown_method(self):
        self.cmd['close']['obj']()

    def test_help(self, capsys):
        self.cmd['help']['obj']()
        self.cmd['clear']['obj']()
        out, err = capsys.readouterr()
        assert re.search(r".* Commands.*", out)
        assert re.search(r".* Modules.*", out)

    def test_notes(self, capsys):
        self.cmd['notes']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: notes \[-h\] .*", out)

        self.cmd['notes']['obj']('-l')
        out, err = capsys.readouterr()
        assert re.search(".*No open session.*", out)

    def test_open(self, capsys):
        self.cmd['open']['obj']('-h')
        self.cmd['open']['obj']('-u', 'https://github.com/viper-framework/viper-test-files/raw/master/test_files/cmd.exe')
        out, err = capsys.readouterr()
        assert re.search("usage: open \[-h\] .*", out)
        assert re.search(".*Session opened on /tmp/.*", out)

    def test_open_tor(self, capsys):
        self.cmd['open']['obj']('-h')
        self.cmd['open']['obj']('-t', '-u', 'https://github.com/viper-framework/viper-test-files/raw/master/test_files/cmd.exe')
        out, err = capsys.readouterr()
        assert re.search("usage: open \[-h\] .*", out)
        assert re.search(".*Session opened on /tmp/.*", out)

    def test_notes_existing(self, capsys):
        self.cmd['open']['obj']('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        Database().add_note(__sessions__.current.file.sha256, 'Note test', 'This is the content')
        self.cmd['notes']['obj']('-l')
        self.cmd['notes']['obj']('-v', '1')
        self.cmd['notes']['obj']('-d', '1')
        out, err = capsys.readouterr()
        assert re.search(".*1  | Note test.*", out)
        assert re.search(".*This is the content.*", out)

    def test_analysis(self, capsys):
        self.cmd['open']['obj']('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        self.cmd['analysis']['obj']('-h')
        self.cmd['analysis']['obj']('-l')
        self.cmd['analysis']['obj']('-v', '1')
        out, err = capsys.readouterr()
        assert re.search("usage: analysis \[-h\] .*", out)
        assert re.search(".*Saved On.*", out)
        assert re.search(".*Cmd Line.*", out)

    def test_store(self, capsys):
        self.cmd['store']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: store \[-h\] .*", out)

    def test_delete(self, capsys):
        self.cmd['delete']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: delete \[-h\] .*", out)

    def test_find(self, capsys):
        self.cmd['find']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: find \[-h\] .*", out)

        self.cmd['find']['obj']('all')
        out, err = capsys.readouterr()
        assert re.search(".*chromeinstall-8u31.exe.*", out)

    def test_tags(self, capsys):
        self.cmd['tags']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: tags \[-h\] .*", out)

    def test_tags_use(self, capsys):
        self.cmd['open']['obj']('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        self.cmd['tags']['obj']('-a', 'mytag')
        self.cmd['tags']['obj']('-d', 'mytag')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(".*Tags added to the currently opened file.*", lines[1])
        assert re.search(".*Refreshing session to update attributes....*", lines[2])

    def test_sessions(self, capsys):
        self.cmd['sessions']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: sessions \[-h\] .*", out)

        self.cmd['sessions']['obj']('-l')
        out, err = capsys.readouterr()
        assert re.search(".*Opened Sessions.*", out)

    def test_projects(self, capsys):
        self.cmd['projects']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: projects \[-h\] .*", out)

        p = Project()
        p.open("project_switch_test1")

        self.cmd['projects']['obj']('-l')
        out, err = capsys.readouterr()
        assert re.search(".*Projects Available.*", out)
        assert re.search(".*project_switch_test1.*", out)
        assert not re.search(".*not_there.*", out)

        self.cmd['projects']['obj']('-s', 'project_switch_test1')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(".*Switched to project.*", lines[0])

        # return to default
        p.open("default")

    def test_export(self, capsys):
        self.cmd['export']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: export \[-h\] .*", out)

    def test_stats(self, capsys):
        self.cmd['stats']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: stats \[-h\] .*", out)

    def test_parent(self, capsys):
        self.cmd['parent']['obj']('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: parent \[-h\] .*", out)

    def test_rename(self, capsys):
        self.cmd['find']['obj']("all")
        out, err = capsys.readouterr()
        assert out == ""

        self.cmd['open']['obj']('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        self.cmd['store']['obj']()
        _, _ = capsys.readouterr()

        if sys.version_info <= (3, 0):
            in_fct = 'builtins.raw_input'
        else:
            in_fct = 'builtins.input'

        with mock.patch(in_fct, return_value='chromeinstall-8u31.exe.new'):
            self.cmd['rename']['obj']()

        out, err = capsys.readouterr()
        lines = out.split('\n')

        assert re.search(r".*Current name is.*1mchromeinstall-8u31.exe.*", lines[0])
        assert re.search(r".*Refreshing session to update attributes.*", lines[1])

    def test_copy(self, capsys):
        self.cmd['projects']['obj']('-s', 'copy_test_dst')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Switched to project.*", lines[0])

        self.cmd['find']['obj']('all')
        out, err = capsys.readouterr()
        assert out == ""

        self.cmd['projects']['obj']('-s', 'copy_test_src')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Switched to project.*", lines[0])

        self.cmd['find']['obj']('all')
        out, err = capsys.readouterr()
        assert out == ""

        self.cmd['open']['obj']('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        self.cmd['store']['obj']()
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*Stored file.*", lines[1])

        self.cmd['find']['obj']('all')
        out, err = capsys.readouterr()
        assert re.search(r".*\| 1 \| chromeinstall-8u31.exe.*", out)
        assert not re.search(r".*\| 2 \|.*", out)

        self.cmd['copy']['obj']('-d', 'copy_test_dst')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Copied:.*", lines[0])
        assert re.search(r".*Deleted:.*", lines[1])
        assert re.search(r".*Successfully copied sample.*", lines[2])

        self.cmd['find']['obj']('all')
        out, err = capsys.readouterr()
        assert out == ""
        assert not re.search(r".*\| 1 \| chromeinstall-8u31.exe.*", out)
        assert not re.search(r".*\| 2 \|.*", out)

        self.cmd['projects']['obj']('-s', 'copy_test_dst')
        out, err = capsys.readouterr()
        assert re.search(r".*Switched to project.*", out)

        self.cmd['find']['obj']('all')
        out, err = capsys.readouterr()
        assert re.search(r".*\| 1 \| chromeinstall-8u31.exe.*", out)
        assert not re.search(r".*\| 2 \|.*", out)
