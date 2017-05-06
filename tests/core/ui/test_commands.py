# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.core.ui import commands
from viper.core.database import Database
from viper.core.project import Project
from tests.conftest import FIXTURE_DIR
import re
import os
import sys

try:
    from unittest import mock
except ImportError:
    # Python2
    import mock


class TestCommands:

    def setup_class(cls):
        instance = commands.Commands()
        instance.cmd_open('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        instance.cmd_store()

    def teardown_method(self):
        instance = commands.Commands()
        instance.cmd_close()

    def test_init(self):
        instance = commands.Commands()
        assert isinstance(instance, commands.Commands)

    def test_help(self, capsys):
        instance = commands.Commands()
        instance.cmd_help()
        instance.cmd_clear()
        out, err = capsys.readouterr()
        assert re.search(r".* Commands.*", out)
        assert re.search(r".* Modules.*", out)

    def test_notes(self, capsys):
        instance = commands.Commands()
        instance.cmd_notes('-h')
        instance.cmd_notes('-l')
        out, err = capsys.readouterr()
        assert re.search("usage: notes \[-h\] .*", out)
        assert re.search(".*No open session.*", out)

    def test_open(self, capsys):
        instance = commands.Commands()
        instance.cmd_open('-h')
        instance.cmd_open('-u', 'https://github.com/viper-framework/viper-test-files/raw/master/test_files/cmd.exe')
        out, err = capsys.readouterr()
        assert re.search("usage: open \[-h\] .*", out)
        assert re.search(".*Session opened on /tmp/.*", out)

    def test_open_tor(self, capsys):
        instance = commands.Commands()
        instance.cmd_open('-h')
        instance.cmd_open('-t', '-u', 'https://github.com/viper-framework/viper-test-files/raw/master/test_files/cmd.exe')
        out, err = capsys.readouterr()
        assert re.search("usage: open \[-h\] .*", out)
        assert re.search(".*Session opened on /tmp/.*", out)

    def test_notes_existing(self, capsys):
        instance = commands.Commands()
        instance.cmd_open('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        Database().add_note(commands.__sessions__.current.file.sha256, 'Note test', 'This is the content')
        instance.cmd_notes('-l')
        instance.cmd_notes('-v', '1')
        instance.cmd_notes('-d', '1')
        out, err = capsys.readouterr()
        assert re.search(".*1  | Note test.*", out)
        assert re.search(".*This is the content.*", out)

    def test_analysis(self, capsys):
        instance = commands.Commands()
        instance.cmd_open('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        instance.cmd_analysis('-h')
        instance.cmd_analysis('-l')
        instance.cmd_analysis('-v', '1')
        out, err = capsys.readouterr()
        assert re.search("usage: analysis \[-h\] .*", out)
        assert re.search(".*Saved On.*", out)
        assert re.search(".*Cmd Line.*", out)

    def test_store(self, capsys):
        instance = commands.Commands()
        instance.cmd_store('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: store \[-h\] .*", out)

    def test_delete(self, capsys):
        instance = commands.Commands()
        instance.cmd_delete('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: delete \[-h\] .*", out)

    def test_find(self, capsys):
        instance = commands.Commands()
        instance.cmd_find('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: find \[-h\] .*", out)

    def test_tags(self, capsys):
        instance = commands.Commands()
        instance.cmd_tags('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: tags \[-h\] .*", out)

    def test_tags_use(self, capsys):
        instance = commands.Commands()
        instance.cmd_open('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        instance.cmd_tags('-a', 'mytag')
        instance.cmd_tags('-d', 'mytag')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(".*Tags added to the currently opened file.*", lines[1])
        assert re.search(".*Refreshing session to update attributes....*", lines[2])

    def test_sessions(self, capsys):
        instance = commands.Commands()
        instance.cmd_sessions('-h')
        instance.cmd_sessions('-l')
        out, err = capsys.readouterr()
        assert re.search("usage: sessions \[-h\] .*", out)
        assert re.search(".*6af69bf32d84229ff9a8904ab8ed28d7.*", out)

    def test_projects(self, capsys):
        instance = commands.Commands()
        instance.cmd_projects('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: projects \[-h\] .*", out)

        p = Project()
        p.open("project_switch_test1")

        instance.cmd_projects('-l')
        out, err = capsys.readouterr()
        assert re.search(".*Projects Available.*", out)
        assert re.search(".*project_switch_test1.*", out)
        assert not re.search(".*not_there.*", out)

        instance.cmd_projects('-s', 'project_switch_test1')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(".*Switched to project.*", lines[0])

        # return to default
        p.open("default")

    def test_export(self, capsys):
        instance = commands.Commands()
        instance.cmd_export('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: export \[-h\] .*", out)

    def test_stats(self, capsys):
        instance = commands.Commands()
        instance.cmd_stats('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: stats \[-h\] .*", out)

    def test_parent(self, capsys):
        instance = commands.Commands()
        instance.cmd_parent('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: parent \[-h\] .*", out)

    def test_rename(self, capsys):
        instance = commands.Commands()

        instance.cmd_find("all")
        out, err = capsys.readouterr()
        assert out == ""

        instance.cmd_open('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        instance.cmd_store()
        _, _ = capsys.readouterr()

        if sys.version_info <= (3, 0):
            in_fct = 'viper.core.ui.commands.input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='chromeinstall-8u31.exe.new'):
            instance.cmd_rename()
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Current name is.*1mchromeinstall-8u31.exe.*", lines[0])
        assert re.search(r".*Refreshing session to update attributes.*", lines[1])

    def test_copy(self, capsys):
        instance = commands.Commands()

        instance.cmd_projects('-s', 'copy_test_dst')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Switched to project.*", lines[0])

        instance.cmd_find('all')
        out, err = capsys.readouterr()
        assert out == ""

        instance.cmd_projects('-s', 'copy_test_src')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Switched to project.*", lines[0])

        instance.cmd_find('all')
        out, err = capsys.readouterr()
        assert out == ""

        instance.cmd_open('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        instance.cmd_store()
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*Stored file.*", lines[1])

        instance.cmd_find('all')
        out, err = capsys.readouterr()
        assert re.search(r".*\| 1 \| chromeinstall-8u31.exe.*", out)
        assert not re.search(r".*\| 2 \|.*", out)

        instance.cmd_copy('-d', 'copy_test_dst')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Copied:.*", lines[0])
        assert re.search(r".*Deleted:.*", lines[1])
        assert re.search(r".*Successfully copied sample.*", lines[2])

        instance.cmd_find('all')
        out, err = capsys.readouterr()
        assert out == ""
        assert not re.search(r".*\| 1 \| chromeinstall-8u31.exe.*", out)
        assert not re.search(r".*\| 2 \|.*", out)

        instance.cmd_projects('-s', 'copy_test_dst')
        out, err = capsys.readouterr()
        assert re.search(r".*Switched to project.*", out)

        instance.cmd_find('all')
        out, err = capsys.readouterr()
        assert re.search(r".*\| 1 \| chromeinstall-8u31.exe.*", out)
        assert not re.search(r".*\| 2 \|.*", out)
