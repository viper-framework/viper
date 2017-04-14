# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.core.ui import commands
import re


class TestCommands:

    def test_init(self):
        instance = commands.Commands()
        assert isinstance(instance, commands.Commands)

    def test_help(self, capsys):
        instance = commands.Commands()
        instance.cmd_help()
        instance.cmd_clear()
        instance.cmd_close()
        out, err = capsys.readouterr()
        assert re.search(r".* Commands.*", out)
        assert re.search(r".* Modules.*", out)

    def test_open(self, capsys):
        instance = commands.Commands()
        instance.cmd_open('-h')
        instance.cmd_open('-u', 'https://github.com/viper-framework/viper-test-files/raw/master/test_files/cmd.exe')
        out, err = capsys.readouterr()
        assert re.search("usage: open \[-h\] .*", out)
        assert re.search(".*Session opened on /tmp/.*", out)

    def test_notes(self, capsys):
        instance = commands.Commands()
        instance.cmd_notes('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: notes \[-h\] .*", out)

    def test_analysis(self, capsys):
        instance = commands.Commands()
        instance.cmd_analysis('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: analysis \[-h\] .*", out)

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

    def test_sessions(self, capsys):
        instance = commands.Commands()
        instance.cmd_sessions('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: sessions \[-h\] .*", out)

    def test_projects(self, capsys):
        instance = commands.Commands()
        instance.cmd_projects('-h')
        out, err = capsys.readouterr()
        assert re.search("usage: projects \[-h\] .*", out)

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
