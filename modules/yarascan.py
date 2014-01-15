import os
import getopt

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __session__
from viper.core.storage import get_sample_path

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

class YaraScan(Module):
    cmd = 'yara'
    description = 'Run Yara scan'

    def scan(self):
        def usage():
            print("usage: yara scan [-a]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--rule (-r)\tSpecify a ruleset file path (default will run data/yara/index.yara)")
            print("\t--all (-a)\tScan all stored files (default if no session is open)")
            print("")

        rule_path = ''
        scan_all = False

        try:
            opts, argv = getopt.getopt(self.args[1:], 'r:a', ['rule=', 'all'])
        except getopt.GetoptError as e:
            print(e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-r', '--rule'):
                rule_path = value
            elif opt in ('-a', '--all'):
                scan_all = True

        # If no custom ruleset is specified, we use the default one.
        if not rule_path:
            rule_path = 'data/yara/index.yara'

        # Check if the selected ruleset actually exists.
        if not os.path.exists(rule_path):
            print_error("No valid Yara ruleset at {0}".format(rule_path))
            return

        # Compile all rules from given ruleset.
        rules = yara.compile(rule_path)
        files = []

        # If there is a session open and the user didn't specifically
        # request to scan the full repository, we just add the currently
        # opened file's path.
        if __session__.is_set() and not scan_all:
            files.append(__session__.file)
        # Otherwise we loop through all files in the repository and queue
        # them up for scan.
        else:
            print_info("Scanning all stored files...")

            db = Database()
            samples = db.find(key='all')

            for sample in samples:
                files.append(sample)

        for entry in files:
            print_info("Scanning {0} ({1})".format(entry.name, entry.sha256))

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
            for match in rules.match(entry_path):
                for string in match.strings:
                    rows.append([match.rule, string[1], string[0], string[2]])

            if rows:
                header = [
                    'Rule',
                    'String',
                    'Offset',
                    'Content'
                ]

                print(table(header=header, rows=rows))

    def rules(self):
        for folder, folders, files in os.walk('data/yara/'):
            for file_name in files:
                print_item(os.path.join(folder, file_name))

    def usage(self):
        print("usage: yara <command>")

    def help(self):
        self.usage()
        print("")
        print("Options:")
        print("\thelp\t\tShow this help message")
        print("\tscan\t\tScan files with Yara signatures")
        print("\trules\t\tOperate on Yara rules")
        print("")

    def run(self):
        if not HAVE_YARA:
            print_error("Missing dependency, install yara")
            return

        if len(self.args) == 0:
            self.help()
            return

        if self.args[0] == 'help':
            self.help()
        elif self.args[0] == 'scan':
            self.scan()
        elif self.args[0] == 'rules':
            self.rules()
