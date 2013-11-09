import os
import getopt

from viper.common.out import *
from viper.common.colors import bold, cyan, white
from viper.core.session import __session__
from viper.core.plugins import __modules__
from viper.core.database import Database
from viper.core.storage import store_sample, get_sample_path

class Commands(object):

    def __init__(self):
        # Open connection to the database.
        self.db = Database()

        # Map commands to their related functions.
        self.commands = dict(
            help=dict(obj=self.cmd_help, description="Show this help message"),
            open=dict(obj=self.cmd_open, description="Open a file"),
            close=dict(obj=self.cmd_close, description="Close the current session"),
            info=dict(obj=self.cmd_info, description="Show information on the opened file"),
            clear=dict(obj=self.cmd_clear, description="Clear the console"),
            store=dict(obj=self.cmd_store, description="Store the opened file to the local repository"),
            delete=dict(obj=self.cmd_delete, description="Delete the opened file"),
            find=dict(obj=self.cmd_find, description="Find a file"),
        )

    ##
    # CLEAR
    #
    # This command simply clears the shell.
    def cmd_clear(self, *args):
        os.system('clear')

    ##
    # HELP
    #
    # This command simply prints the help message.
    # It lists both embedded commands and loaded modules.
    def cmd_help(self, *args):
        print(bold("Commands:"))

        rows = []
        for command_name, command_item in self.commands.items():
            rows.append([command_name, command_item['description']])

        print(table(['Command', 'Description'], rows))       
        print("")
        print(bold("Modules:"))

        rows = []
        for module_name, module_item in __modules__.items():
            rows.append([module_name, module_item['description']])

        print(table(['Command', 'Description'], rows))

    ##
    # OPEN
    #
    # This command is used to open a session on a given file.
    # It either can be an external file path, or a SHA256 hash of a file which
    # has been previously imported and stored.
    # While the session is active, every operation and module executed will be
    # run against the file specified.
    def cmd_open(self, *args):
        def usage():
            print("usage: open [-h] [-f] target")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--file (-f)\tThe target is a file")
            print("")

        try:
            opts, argv = getopt.getopt(args, 'hf', ['help', 'file'])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        is_file = False

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-f', '--file'):
                is_file = True

        if len(argv) == 0:
            usage()
            return
        else:
            target = argv[0]

        if is_file:
            target = os.path.expanduser(target)

            if not os.path.exists(target) or not os.path.isfile(target):
                print_error("File not found")
                return

            __session__.set(target)
        else:
            target = argv[0].strip().lower()
            path = get_sample_path(target)
            if path:
                __session__.set(path)

    ##
    # CLOSE
    #
    # This command resets the open session.
    # After that, all handles to the opened file should be closed and the
    # shell should be restored to the default prompt.
    def cmd_close(self, *args):
        __session__.clear()

    ##
    # INFO
    #
    # This command returns information on the open session. It returns details
    # on the file (e.g. hashes) and other information that might available from
    # the database.
    def cmd_info(self, *args):
        if __session__.is_set():
            print(table(
                ['Key', 'Value'],
                [
                    ('Name', __session__.file.name),
                    ('Path', __session__.file.path),
                    ('Size', __session__.file.size),
                    ('Type', __session__.file.type),
                    ('MD5', __session__.file.md5),
                    ('SHA1', __session__.file.sha1),
                    ('SHA256', __session__.file.sha256),
                    ('SHA512', __session__.file.sha512),
                    ('SSdeep', __session__.file.ssdeep),
                    ('CRC32', __session__.file.crc32)
                ]
            ))

    ##
    # STORE
    #
    # This command stores the opened file in the local repository and tries
    # to store details in the database.
    def cmd_store(self, *args):
        # TODO: Add tags argument.
        if __session__.is_set():
            # Store file to the local repository.
            new_path = store_sample(__session__.file)
            # Add file to the database.
            status = self.db.add(__session__.file)

            print_success("Stored to: {0}".format(new_path))

            # Open session to the new file.
            self.cmd_open(*[__session__.file.sha256])

    ##
    # DELETE
    #
    # This commands deletes the currenlty opened file (only if it's stored in
    # the local repository) and removes the details from the database
    def cmd_delete(self, *args):
        if __session__.is_set():
            while True:
                choice = raw_input("Are you sure you want to delete this binary? Can't be reverted! [y/n] ")
                if choice == 'y':
                    break
                elif choice == 'n':
                    return

            rows = self.db.find('sha256', __session__.file.sha256)
            if rows:
                malware_id = rows[0].id
                if self.db.delete(malware_id):
                    print_success("File deleted")
                else:
                    print_error("Unable to delete file")

            os.remove(get_sample_path(__session__.file.sha256))
            __session__.clear()

    ##
    # FIND
    #
    # This command is used to search for files in the database.
    def cmd_find(self, *args):
        if len(args) == 0:
            print_error("Invalid search term")
            return

        key = args[0]
        try:
            value = args[1]
        except IndexError:
            value = None

        items = self.db.find(key, value)
        if not items:
            return

        rows = []
        for item in items:
            rows.append([item.name, item.type, item.size, item.sha256])

        print(table(['Name', 'Type', 'Size', 'SHA256'], rows))
