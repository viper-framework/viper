# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import tempfile
import string as printstring  # string is being used as a var - easier to replace here

try:
    from scandir import walk
except ImportError:
    from os import walk

from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __sessions__
from viper.core.storage import get_sample_path
from viper.common.constants import VIPER_ROOT

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


class YaraScan(Module):
    cmd = 'yara'
    description = 'Run Yara scan'
    authors = ['nex']

    def __init__(self):
        super(YaraScan, self).__init__()
        subparsers = self.parser.add_subparsers(dest='subname')
        parser_scan = subparsers.add_parser('scan', help='Scan files with Yara signatures')
        parser_scan.add_argument('-r', '--rule', help='Specify a ruleset file path (default will run data/yara/index.yara)')
        parser_scan.add_argument('-a', '--all', action='store_true', help='Scan all stored files (default if no session is open)')
        parser_scan.add_argument('-t', '--tag', action='store_true', help='Tag Files with Rule Name (default is not to)')

        parser_rules = subparsers.add_parser('rules', help='Operate on Yara rules')
        parser_rules.add_argument('-e', '--edit', help='Open an editor to edit the specified rule')

        for folder in ['/usr/share/viper/yara', os.path.join(VIPER_ROOT, 'data/yara')]:
            if os.path.exists(folder):
                self.rule_path = folder
                break

    def scan(self):

        def string_printable(line):
            line = str(line)
            new_line = ''
            for c in line:
                if c in printstring.printable:
                    new_line += c
                else:
                    new_line += '\\x' + c.encode('hex')
            return new_line

        # This means users can just drop or remove rule files without
        # having to worry about maintaining the index.
        # TODO: make paths absolute.
        # TODO: this regenerates the file at every run, perhaps we
        # could find a way to optimize this.
        def rule_index():
            tmp_path = os.path.join(tempfile.gettempdir(), 'index.yara')
            with open(tmp_path, 'w') as rules_index:
                for rule_file in os.listdir(self.rule_path):
                    # Skip if the extension is not right, could cause problems.
                    if not rule_file.endswith('.yar') and not rule_file.endswith('.yara'):
                        continue
                    # Skip if it's the index itself.
                    if rule_file == 'index.yara':
                        continue

                    # Add the rule to the index.
                    line = 'include "{0}"\n'.format(os.path.join(self.rule_path, rule_file))
                    rules_index.write(line)

            return tmp_path

        arg_rule = self.args.rule
        arg_scan_all = self.args.all
        arg_tag = self.args.tag

        # If no custom ruleset is specified, we use the default one.
        if not arg_rule:
            arg_rule = rule_index()

        # Check if the selected ruleset actually exists.
        if not os.path.exists(arg_rule):
            self.log('error', "No valid Yara ruleset at {0}".format(arg_rule))
            return

        # Compile all rules from given ruleset.
        rules = yara.compile(arg_rule)
        files = []

        # If there is a session open and the user didn't specifically
        # request to scan the full repository, we just add the currently
        # opened file's path.
        if __sessions__.is_set() and not arg_scan_all:
            files.append(__sessions__.current.file)
        # Otherwise we loop through all files in the repository and queue
        # them up for scan.
        else:
            self.log('info', "Scanning all stored files...")

            db = Database()
            samples = db.find(key='all')

            for sample in samples:
                files.append(sample)

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
            for match in rules.match(entry_path):
                # Add a row for each string matched by the rule.
                for string in match.strings:
                    rows.append([match.rule, string_printable(string[1]), string_printable(string[0]), string_printable(string[2])])

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

            if rows:
                header = [
                    'Rule',
                    'String',
                    'Offset',
                    'Content'
                ]
                self.log('table', dict(header=header, rows=rows))

            # If we selected to add tags do that now.
            if rows and arg_tag:
                db = Database()
                for tag in tag_list:
                    db.add_tags(tag[0], tag[1])

                # If in a session reset the session to see tags.
                if __sessions__.is_set() and not arg_scan_all:
                    self.log('info', "Refreshing session to update attributes...")
                    __sessions__.new(__sessions__.current.file.path)

    def rules(self):
        arg_edit = self.args.edit

        # Retrieve the list of rules and populate a list.
        rules = []
        count = 1
        for folder, folders, files in walk(self.rule_path):
            for file_name in files:
                rules.append([count, os.path.join(folder, file_name)])
                count += 1

        # If the user wants to edit a specific rule, loop through all of them
        # identify which one to open, and launch the default editor.
        if arg_edit:
            for rule in rules:
                if int(arg_edit) == rule[0]:
                    os.system('"${EDITOR:-nano}" ' + rule[1])
                    break
        # Otherwise, just print the list.
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
