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
        commands.Open().run('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        commands.Store().run()

    def teardown_method(self):
        commands.Close().run()

    def test_init(self):
        instance = commands.Commands()
        assert isinstance(instance, commands.Commands)

    def test_help(self, capsys):
        commands.Help().run()
        commands.Clear().run()
        out, err = capsys.readouterr()
        assert re.search(r".* Commands.*", out)
        assert re.search(r".* Modules.*", out)

    def test_notes(self, capsys):
        commands.Notes().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: notes \[-h\] .*", out)

        commands.Notes().run('-l')
        out, err = capsys.readouterr()
        assert re.search(".*No open session.*", out)

    def test_open(self, capsys):
        commands.Open().run('-h')
        commands.Open().run('-u', 'https://github.com/viper-framework/viper-test-files/raw/master/test_files/cmd.exe')
        out, err = capsys.readouterr()
        assert re.search("usage: open \[-h\] .*", out)
        assert re.search(".*Session opened on /tmp/.*", out)

    def test_open_tor(self, capsys):
        commands.Open().run('-h')
        commands.Open().run('-t', '-u', 'https://github.com/viper-framework/viper-test-files/raw/master/test_files/cmd.exe')
        out, err = capsys.readouterr()
        assert re.search("usage: open \[-h\] .*", out)
        assert re.search(".*Session opened on /tmp/.*", out)

    def test_notes_existing(self, capsys):
        commands.Open().run('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        Database().add_note(commands.__sessions__.current.file.sha256, 'Note test', 'This is the content')
        commands.Notes().run('-l')
        commands.Notes().run('-v', '1')
        commands.Notes().run('-d', '1')
        out, err = capsys.readouterr()
        assert re.search(".*1  | Note test.*", out)
        assert re.search(".*This is the content.*", out)

    def test_analysis(self, capsys):
        commands.Open().run('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        commands.Analysis().run('-h')
        commands.Analysis().run('-l')
        commands.Analysis().run('-v', '1')
        out, err = capsys.readouterr()
        assert re.search("usage: analysis \[-h\] .*", out)
        assert re.search(".*Saved On.*", out)
        assert re.search(".*Cmd Line.*", out)

    def test_store(self, capsys):
        commands.Store().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: store \[-h\] .*", out)

    def test_delete(self, capsys):
        commands.Delete().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: delete \[-h\] .*", out)

    def test_find(self, capsys):
        commands.Find().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: find \[-h\] .*", out)

        commands.Find().run('all')
        out, err = capsys.readouterr()
        assert re.search(".*chromeinstall-8u31.exe.*", out)

    def test_tags(self, capsys):
        commands.Tags().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: tags \[-h\] .*", out)

    def test_tags_use(self, capsys):
        commands.Open().run('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        commands.Tags().run('-a', 'mytag')
        commands.Tags().run('-d', 'mytag')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(".*Tags added to the currently opened file.*", lines[1])
        assert re.search(".*Refreshing session to update attributes....*", lines[2])

    def test_sessions(self, capsys):
        commands.Sessions().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: sessions \[-h\] .*", out)

        commands.Sessions().run('-l')
        out, err = capsys.readouterr()
        assert re.search(".*Opened Sessions.*", out)

    def test_projects(self, capsys):
        commands.Projects().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: projects \[-h\] .*", out)

        p = Project()
        p.open("project_switch_test1")

        commands.Projects().run('-l')
        out, err = capsys.readouterr()
        assert re.search(".*Projects Available.*", out)
        assert re.search(".*project_switch_test1.*", out)
        assert not re.search(".*not_there.*", out)

        commands.Projects().run('-s', 'project_switch_test1')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(".*Switched to project.*", lines[0])

        # return to default
        p.open("default")

    def test_export(self, capsys):
        commands.Export().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: export \[-h\] .*", out)

    def test_stats(self, capsys):
        commands.Stats().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: stats \[-h\] .*", out)

    def test_parent(self, capsys):
        commands.Parent().run('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: parent \[-h\] .*", out)

    def test_rename(self, capsys):
        commands.Find().run("all")
        out, err = capsys.readouterr()
        assert out == ""

        commands.Open().run('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        commands.Store().run()
        _, _ = capsys.readouterr()

        if sys.version_info <= (3, 0):
            in_fct = 'viper.core.ui.commands.input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='chromeinstall-8u31.exe.new'):
            commands.Rename().run()
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Current name is.*1mchromeinstall-8u31.exe.*", lines[0])
        assert re.search(r".*Refreshing session to update attributes.*", lines[1])

    def test_copy(self, capsys):
        commands.Projects().run('-s', 'copy_test_dst')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Switched to project.*", lines[0])

        commands.Find().run('all')
        out, err = capsys.readouterr()
        assert out == ""

        commands.Projects().run('-s', 'copy_test_src')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Switched to project.*", lines[0])

        commands.Find().run('all')
        out, err = capsys.readouterr()
        assert out == ""

        commands.Open().run('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        commands.Store().run()
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Session opened on.*", lines[0])
        assert re.search(r".*Stored file.*", lines[1])

        commands.Find().run('all')
        out, err = capsys.readouterr()
        assert re.search(r".*\| 1 \| chromeinstall-8u31.exe.*", out)
        assert not re.search(r".*\| 2 \|.*", out)

        commands.Copy().run('-d', 'copy_test_dst')
        out, err = capsys.readouterr()
        lines = out.split('\n')
        assert re.search(r".*Copied:.*", lines[0])
        assert re.search(r".*Deleted:.*", lines[1])
        assert re.search(r".*Successfully copied sample.*", lines[2])

        commands.Find().run('all')
        out, err = capsys.readouterr()
        assert out == ""
        assert not re.search(r".*\| 1 \| chromeinstall-8u31.exe.*", out)
        assert not re.search(r".*\| 2 \|.*", out)

        commands.Projects().run('-s', 'copy_test_dst')
        out, err = capsys.readouterr()
        assert re.search(r".*Switched to project.*", out)

        commands.Find().run('all')
        out, err = capsys.readouterr()
        assert re.search(r".*\| 1 \| chromeinstall-8u31.exe.*", out)
        assert not re.search(r".*\| 2 \|.*", out)
