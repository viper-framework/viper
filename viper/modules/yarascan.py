# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import string
import subprocess
from os.path import expanduser

try:
    from scandir import walk
except ImportError:
    from os import walk

from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __sessions__
from viper.core.storage import get_sample_path
from viper.core.config import Config

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

cfg = Config()


def string_printable(line):
    line = str(line)
    new_line = ''
    for c in line:
        if c in string.printable:
            new_line += c
        else:
            new_line += '\\x' + c.encode('hex')
    return new_line


class YaraScan(Module):
    cmd = 'yara'
    description = 'Scan stored files with Yara rules'
    authors = ['nex']

    def __init__(self):
        super(YaraScan, self).__init__()
        subparsers = self.parser.add_subparsers(dest='subname')
        parser_scan = subparsers.add_parser('scan', help='Scan files with Yara signatures')
        parser_scan.add_argument('-r', '--rule', help='Specify a ruleset file path (if none is specified, the rules in local storage are used)')
        parser_scan.add_argument('-a', '--all', action='store_true', help='Scan all stored files (default if no session is open)')
        parser_scan.add_argument('-t', '--tag', action='store_true', help='Tag Files with Rule Name (default is not to)')
        parser_scan.add_argument('-v', '--verbose', action='store_true', help='Output a detailed overview of the matches and found offsets')

        parser_rules = subparsers.add_parser('rules', help='Operate on Yara rules')
        parser_rules.add_argument('-e', '--edit', help='Open an editor to edit the specified rule')
        parser_rules.add_argument('-u', '--update', action='store_true', help='Download latest rules from selected repositories')

        self.local_rules = os.path.join(expanduser('~'), '.viper', 'data', 'yara')
        self.rules_paths = [
            '/usr/share/viper/yara',
            self.local_rules
        ]

    def _get_rules(self):
        # Retrieve the list of rules and populate a list.
        rules = []
        count = 1

        # We loop through all rules paths (both in share as well as locally)
        # and we populate the list of rules.
        for root in self.rules_paths:
            for folder, folders, files in walk(root):
                for file_name in files:
                    # Skip if the extension is not right, could cause problems.
                    if not file_name.endswith('.yar') and not file_name.endswith('.yara'):
                        continue

                    rules.append([count, os.path.join(folder, file_name)])
                    count += 1

        return rules

    def scan(self):
        arg_rule = self.args.rule
        arg_scan_all = self.args.all
        arg_tag = self.args.tag
        arg_verbose = self.args.verbose

        externals = {'filename': '', 'filepath': '', 'extension': '', 'filetype': ''}

        # If a rule file is specified we compile that, otherwise all
        # the rules we have stored locally.
        if arg_rule:
            # Check if the selected ruleset actually exists.
            if not os.path.exists(arg_rule):
                self.log('error', "The specified file does not exist at path {0}".format(arg_rule))
                return

            rules = yara.compile(arg_rule, externals=externals)
        # Otherwise, we get all the rules that are stored locally and we
        # load them in different namespaces.
        else:
            filepaths = dict()
            for rule in self._get_rules():
                filepaths['namespace' + str(rule[0])] = rule[1]

            rules = yara.compile(filepaths=filepaths, externals=externals, includes=False)

        # Files to scan.
        files = []

        # If there is a session open and the user didn't specifically
        # request to scan the full repository, we just add the currently
        # opened file's path.
        if __sessions__.is_set() and not arg_scan_all:
            files.append(__sessions__.current.file)
        # Otherwise we loop through all files in the repository and queue
        # them up for scan.
        else:
            self.log('info', "Scanning all stored files (in the current project)...")

            db = Database()
            samples = db.find(key='all')

            for sample in samples:
                files.append(sample)

        # Loop through all files to be scanned.
        for entry in files:
            if entry.size == 0:
                continue

            self.log('info', "Scanning {0} ({1})".format(entry.name, entry.sha256))

            # Check if the entry has a path attribute. This happens when
            # there is a session open. We need to distinguish this just for
            # the cases where we're scanning an opened file which has not been
            # stored yet.
            if hasattr(entry, 'path'):
                entry_path = entry.path
            # This should be triggered only when scanning the full repository.
            else:
                entry_path = get_sample_path(entry.sha256)

            # Check if the file exists before running the yara scan.
            if not os.path.exists(entry_path):
                self.log('error', "The file does not exist at path {0}".format(entry_path))
                return

            rows = []
            tag_list = []
            found = False

            # We need this just for some Yara rules.
            try:
                ext = os.path.splitext(entry.name)[1]
            except:
                ext = ''

            for match in rules.match(entry_path, externals={'filename': entry.name, 'filepath': entry_path, 'extension': ext, 'filetype': entry.type}):
                found = True
                # Add a row for each string matched by the rule.
                if arg_verbose:
                    for match_string in match.strings:
                        rows.append([
                            match.rule,
                            string_printable(match_string[1]),
                            string_printable(match_string[0]),
                            string_printable(match_string[2])]
                        )
                else:
                    self.log('item', match.rule)
                # Add matching rules to our list of tags.
                # First it checks if there are tags specified in the metadata
                # of the Yara rule.
                match_tags = match.meta.get('tags')
                # If not, use the rule name.
                # TODO: as we add more and more yara rules, we might remove
                # this option and only tag the file with rules that had
                # tags specified in them.
                if not match_tags:
                    match_tags = match.rule

                # Add the tags to the list.
                tag_list.append([entry.sha256, match_tags])

            if arg_verbose and rows:
                header = [
                    'Rule',
                    'String',
                    'Offset',
                    'Content'
                ]
                self.log('table', dict(header=header, rows=rows))
            # If we selected to add tags do that now.
            if found and arg_tag:
                db = Database()
                for tag in tag_list:
                    db.add_tags(tag[0], tag[1])

                # If in a session reset the session to see tags.
                if __sessions__.is_set() and not arg_scan_all:
                    self.log('info', "Refreshing session to update attributes...")
                    __sessions__.new(__sessions__.current.file.path)

    def rules(self):
        arg_edit = self.args.edit
        arg_update = self.args.update

        rules = self._get_rules()

        # If the user wants to edit a specific rule, loop through all of them
        # identify which one to open, and launch the default editor.
        if arg_edit:
            for rule in rules:
                if int(arg_edit) == rule[0]:
                    os.system('"${EDITOR:-nano}" ' + rule[1])
                    break
        # Otherwise, just print the list.
        # Check if the user wants to update rules.
        elif arg_update:
            # FIrst we create the local rules folder in case it doesn't exist.
            if not os.path.exists(self.local_rules):
                os.makedirs(self.local_rules)

            # TODO: we definitely need a way for Config to parse lists appropriately.
            urls = cfg.yara.repositories.split('\n')
            for url in urls:
                url = url.strip()

                self.log('info', "Updating Yara rules from repository {}".format(url))

                repo_name = url.rsplit('/', 1)[-1].rstrip('.git')
                repo_path = os.path.join(self.local_rules, repo_name)

                # If the repository has been cloned before, we gonna update it.
                if os.path.exists(repo_path):
                    proc = subprocess.Popen(['git', 'pull'], cwd=repo_path)
                # Otherwise, do first clone.
                else:
                    proc = subprocess.Popen(['git', 'clone', url], cwd=self.local_rules)

                proc.wait()
        else:
            self.log('table', dict(header=['#', 'Path'], rows=rules))
            self.log('', "")
            self.log('', "You can edit these rules by specifying --edit and the #")

    def run(self):
        super(YaraScan, self).run()
        if self.args is None:
            return

        if not HAVE_YARA:
            self.log('error', "Missing dependency, install yara")
            return

        if self.args.subname == 'scan':
            self.scan()
        elif self.args.subname == 'rules':
            self.rules()
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
