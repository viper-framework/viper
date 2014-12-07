# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt
import string as printstring # string is being used as a var - easier to replace here

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __sessions__
from viper.core.storage import get_sample_path

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

class YaraScan(Module):
    cmd = 'yara'
    description = 'Run Yara scan'
    authors = ['nex']

    def scan(self):
        def usage():
            self.log('', "usage: yara scan [-a]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--rule (-r)\tSpecify a ruleset file path (default will run data/yara/index.yara)")
            self.log('', "\t--all (-a)\tScan all stored files (default if no session is open)")
            self.log('', "\t--tag (-t)\tTag Files with Rule Name (default is not to)")
            self.log('', "")

        def string_printable(line):
            line = str(line)
            new_line = ''
            for c in line:
                if c in printstring.printable:
                    new_line += c
                else:
                    new_line += '\\x'+c.encode('hex')
            return new_line

        # This means users can just drop or remove rule files without
        # having to worry about maintaining the index.
        # TODO: make paths absolute.
        # TODO: this regenerates the file at every run, perhaps we
        # could find a way to optimize this.
        def rule_index():
            with open('data/yara/index.yara', 'w') as rules_index:
                for rule_file in os.listdir('data/yara'):
                    # Skip if the extension is not right, could cause problems.
                    if not rule_file.endswith('.yar') and not rule_file.endswith('.yara'):
                        continue
                    # Skip if it's the index itself.
                    if rule_file == 'index.yara':
                        continue

                    # Add the rule to the index.
                    line = 'include "{0}"\n'.format(rule_file)
                    rules_index.write(line)

            return 'data/yara/index.yara'

        arg_rule = ''
        arg_scan_all = False
        arg_tag = False

        try:
            opts, argv = getopt.getopt(self.args[1:], 'hr:at', ['help', 'rule=', 'all', 'tag'])
        except getopt.GetoptError as e:
            self.log('', e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            if opt in ('-t', '--tag'):
                arg_tag = True
            elif opt in ('-r', '--rule'):
                arg_rule = value
            elif opt in ('-a', '--all'):
                arg_scan_all = True


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
            if entry.size == 0: continue
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
        def usage():
            self.log('', "usage: yara rules [-h] [-e <rule #>]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--edit (-e)\tOpen an editor to edit the specified rule")
            self.log('', "")

        try:
            opts, argv = getopt.getopt(self.args[1:], 'he:', ['help', 'edit='])
        except getopt.GetoptError as e:
            self.log('', e)
            return

        arg_edit = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-e', '--edit'):
                arg_edit = value

        # Retrieve the list of rules and populatea list.
        rules = []
        count = 1
        for folder, folders, files in os.walk('data/yara/'):
            for file_name in files:
                rules.append([count, os.path.join(folder, file_name)])
                count += 1

        # If the user wnats to edit a specific rule, loop through all of them
        # identify which one to open, and launch the default editor.
        if arg_edit:
            for rule in rules:
                if int(arg_edit) == rule[0]:
                    os.system('"${EDITOR:-nano}" ' + rule[1])
        # Otherwise, just print the list.
        else:
            self.log('table', dict(header=['#', 'Path'], rows=rules))
            self.log('', "")
            self.log('', "You can edit these rules by specifying --edit and the #")

    def run(self):
        if not HAVE_YARA:
            self.log('error', "Missing dependency, install yara")
            return

        def usage():
            self.log('', "usage: yara <help|scan|rules>")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\thelp\t\tShow this help message")
            self.log('', "\tscan\t\tScan files with Yara signatures")
            self.log('', "\trules\t\tOperate on Yara rules")
            self.log('', "")

        if len(self.args) == 0:
            usage()
            return

        if self.args[0] == 'help':
            help()
        elif self.args[0] == 'scan':
            self.scan()
        elif self.args[0] == 'rules':
            self.rules()
        else:
            usage()
