# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import time
import getopt
import fnmatch
import tempfile
import shutil
from zipfile import ZipFile

from viper.common.out import *
from viper.common.objects import File
from viper.common.network import download
from viper.core.session import __sessions__
from viper.core.project import __project__
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
            notes=dict(obj=self.cmd_notes, description="View, add and edit notes on the opened file"),
            clear=dict(obj=self.cmd_clear, description="Clear the console"),
            store=dict(obj=self.cmd_store, description="Store the opened file to the local repository"),
            delete=dict(obj=self.cmd_delete, description="Delete the opened file"),
            find=dict(obj=self.cmd_find, description="Find a file"),
            tags=dict(obj=self.cmd_tags, description="Modify tags of the opened file"),
            sessions=dict(obj=self.cmd_sessions, description="List or switch sessions"),
            projects=dict(obj=self.cmd_projects, description="List or switch existing projects"),
            export=dict(obj=self.cmd_export, description="Export the current session to file or zip"),
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

        rows.append(["exit, quit", "Exit Viper"])
        rows = sorted(rows, key=lambda entry: entry[0])

        print(table(['Command', 'Description'], rows))
        print("")
        print(bold("Modules:"))

        rows = []
        for module_name, module_item in __modules__.items():
            rows.append([module_name, module_item['description']])

        rows = sorted(rows, key=lambda entry: entry[0])

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
            print("usage: open [-h] [-f] [-u] [-l] [-t] <target|md5|sha256>")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--file (-f)\tThe target is a file")
            print("\t--url (-u)\tThe target is a URL")
            print("\t--last (-l)\tThe target is the entry number from the last find command's results")
            print("\t--tor (-t)\tDownload the file through Tor")
            print("")
            print("You can also specify a MD5 or SHA256 hash to a previously stored")
            print("file in order to open a session on it.")
            print("")

        try:
            opts, argv = getopt.getopt(args, 'hfult', ['help', 'file', 'url', 'last', 'tor'])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        arg_is_file = False
        arg_is_url = False
        arg_last = False
        arg_use_tor = False

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-f', '--file'):
                arg_is_file = True
            elif opt in ('-u', '--url'):
                arg_is_url = True
            elif opt in ('-l', '--last'):
                arg_last = True
            elif opt in ('-t', '--tor'):
                arg_use_tor = True

        if len(argv) == 0:
            usage()
            return
        else:
            target = argv[0]

        # If it's a file path, open a session on it.
        if arg_is_file:
            target = os.path.expanduser(target)

            # This is kind of hacky. It checks if there are additional arguments
            # to the open command, if there is I assume that it's the continuation
            # of a filename with spaces. I then concatenate them.
            # TODO: improve this.
            if len(argv) > 1:
                for arg in argv[1:]:
                    target += ' ' + arg

            if not os.path.exists(target) or not os.path.isfile(target):
                print_error("File not found: {0}".format(target))
                return

            __sessions__.new(target)
        # If it's a URL, download it and open a session on the temporary
        # file.
        elif arg_is_url:
            data = download(url=target, tor=arg_use_tor)

            if data:
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.write(data)
                tmp.close()

                __sessions__.new(tmp.name)
        # Try to open the specified file from the list of results from
        # the last find command.
        elif arg_last:
            if __sessions__.find:
                count = 1
                for item in __sessions__.find:
                    if count == int(target):
                        __sessions__.new(get_sample_path(item.sha256))
                        break

                    count += 1
            else:
                print_warning("You haven't performed a find yet")
        # Otherwise we assume it's an hash of an previously stored sample.
        else:
            target = argv[0].strip().lower()

            if len(target) == 32:
                key = 'md5'
            elif len(target) == 64:
                key = 'sha256'
            else:
                usage()
                return

            rows = self.db.find(key=key, value=target)

            if not rows:
                print_warning("No file found with the given hash {0}".format(target))
                return

            path = get_sample_path(rows[0].sha256)
            if path:
                __sessions__.new(path)

    ##
    # CLOSE
    #
    # This command resets the open session.
    # After that, all handles to the opened file should be closed and the
    # shell should be restored to the default prompt.
    def cmd_close(self, *args):
        __sessions__.close()

    ##
    # INFO
    #
    # This command returns information on the open session. It returns details
    # on the file (e.g. hashes) and other information that might available from
    # the database.
    def cmd_info(self, *args):
        if __sessions__.is_set():
            print(table(
                ['Key', 'Value'],
                [
                    ('Name', __sessions__.current.file.name),
                    ('Tags', __sessions__.current.file.tags),
                    ('Path', __sessions__.current.file.path),
                    ('Size', __sessions__.current.file.size),
                    ('Type', __sessions__.current.file.type),
                    ('Mime', __sessions__.current.file.mime),
                    ('MD5', __sessions__.current.file.md5),
                    ('SHA1', __sessions__.current.file.sha1),
                    ('SHA256', __sessions__.current.file.sha256),
                    ('SHA512', __sessions__.current.file.sha512),
                    ('SSdeep', __sessions__.current.file.ssdeep),
                    ('CRC32', __sessions__.current.file.crc32)
                ]
            ))

    ##
    # NOTES
    #
    # This command allows you to view, add, modify and delete notes associated
    # with the currently opened file.
    def cmd_notes(self, *args):
        def usage():
            print("usage: notes [-h] [-l] [-a] [-e <note id>] [-d <note id>]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--list (-l)\tList all notes available for the current file")
            print("\t--add (-a)\tAdd a new note to the current file")
            print("\t--view (-v)\tView the specified note")
            print("\t--edit (-e)\tEdit an existing note")
            print("\t--delete (-d)\tDelete an existing note")
            print("")

        try:
            opts, argv = getopt.getopt(args, 'hlav:e:d:', ['help', 'list', 'add', 'view=', 'edit=', 'delete='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        arg_list = False
        arg_add = False
        arg_view = None
        arg_edit = None
        arg_delete = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-l', '--list'):
                arg_list = True
            elif opt in ('-a', '--add'):
                arg_add = True
            elif opt in ('-v', '--view'):
                arg_view = value
            elif opt in ('-e', '--edit'):
                arg_edit = value
            elif opt in ('-d', '--delete'):
                arg_delete = value

        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if arg_list:
            # Retrieve all notes for the currently opened file.
            malware = Database().find(key='sha256', value=__sessions__.current.file.sha256)
            if not malware:
                print_error("The opened file doesn't appear to be in the database, have you stored it yet?")
                return

            notes = malware[0].note
            if not notes:
                print_info("No notes available for this file yet")
                return

            # Populate table rows.
            rows = []
            for note in notes:
                rows.append([note.id, note.title])

            # Display list of existing notes.
            print(table(header=['ID', 'Title'], rows=rows))

        elif arg_add:
            title = raw_input("Enter a title for the new note: ")

            # Create a new temporary file.
            tmp = tempfile.NamedTemporaryFile(delete=False)
            # Open the temporary file with the default editor, or with nano.
            os.system('"${EDITOR:-nano}" ' + tmp.name)
            # Once the user is done editing, we need to read the content and
            # store it in the database.
            body = tmp.read()
            Database().add_note(__sessions__.current.file.sha256, title, body)
            # Finally, remove the temporary file.
            os.remove(tmp.name)

            print_info("New note with title \"{0}\" added to the current file".format(bold(title)))

        elif arg_view:
            # Retrieve note wth the specified ID and print it.
            note = Database().get_note(arg_view)
            if note:
                print_info(bold('Title: ') + note.title)
                print_info(bold('Body:'))
                print(note.body)
            else:
                print_info("There is no note with ID {0}".format(arg_view))


        elif arg_edit:
            # Retrieve note with the specified ID.
            note = Database().get_note(arg_edit)
            if note:
                # Create a new temporary file.
                tmp = tempfile.NamedTemporaryFile(delete=False)
                # Write the old body to the temporary file.
                tmp.write(note.body)
                tmp.close()
                # Open the old body with the text editor.
                os.system('"${EDITOR:-nano}" ' + tmp.name)
                # Read the new body from the temporary file.
                body = open(tmp.name, 'r').read()
                # Update the note entry with the new body.
                Database().edit_note(arg_edit, body)
                # Remove the temporary file.
                os.remove(tmp.name)

                print_info("Updated note with ID {0}".format(arg_edit))

        elif arg_delete:
            # Delete the note with the specified ID.
            Database().delete_note(arg_delete)
        else:
            usage()

    ##
    # STORE
    #
    # This command stores the opened file in the local repository and tries
    # to store details in the database.
    def cmd_store(self, *args):
        def usage():
            print("usage: store [-h] [-d] [-f <path>] [-s <size>] [-y <type>] [-n <name>] [-t]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--delete (-d)\tDelete the original file")
            print("\t--folder (-f)\tSpecify a folder to import")
            print("\t--file-size (-s)\tSpecify a maximum file size")
            print("\t--file-type (-y)\tSpecify a file type pattern")
            print("\t--file-name (-n)\tSpecify a file name pattern")
            print("\t--tags (-t)\tSpecify a list of comma-separated tags")
            print("")

        try:
            opts, argv = getopt.getopt(args, 'hdf:s:y:n:t:', ['help', 'delete', 'folder=', 'file-size=', 'file-type=', 'file-name=', 'tags='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        arg_delete = False
        arg_folder = False
        arg_file_size = None
        arg_file_type = None
        arg_file_name = None
        arg_tags = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-d', '--delete'):
                arg_delete = True
            elif opt in ('-f', '--folder'):
                arg_folder = value
            elif opt in ('-s', '--file-size'):
                arg_file_size = value
            elif opt in ('-y', '--file-type'):
                arg_file_type = value
            elif opt in ('-n', '--file-name'):
                arg_file_name = value
            elif opt in ('-t', '--tags'):
                arg_tags = value

        def add_file(obj, tags=None):
            if get_sample_path(obj.sha256):
                print_warning("Skip, file \"{0}\" appears to be already stored".format(obj.name))
                return False

            # Try to store file object into database.
            status = self.db.add(obj=obj, tags=tags)
            if status:
                # If succeeds, store also in the local repository.
                # If something fails in the database (for example unicode strings)
                # we don't want to have the binary lying in the repository with no
                # associated database record.
                new_path = store_sample(obj)
                print_success("Stored file \"{0}\" to {1}".format(obj.name, new_path))
            else:
                return False

            # Delete the file if requested to do so.
            if arg_delete:
                try:
                    os.unlink(obj.path)
                except Exception as e:
                    print_warning("Failed deleting file: {0}".format(e))

            return True

        # If the user specified the --folder flag, we walk recursively and try
        # to add all contained files to the local repository.
        # This is note going to open a new session.
        # TODO: perhaps disable or make recursion optional?
        if arg_folder:
            # Check if the specified folder is valid.
            if os.path.isdir(arg_folder):
                # Walk through the folder and subfolders.
                for dir_name, dir_names, file_names in os.walk(arg_folder):
                    # Add each collected file.
                    for file_name in file_names:
                        file_path = os.path.join(dir_name, file_name)

                        if not os.path.exists(file_path):
                            continue
                        # Check if file is not zero.
                        if not os.path.getsize(file_path) > 0:
                            continue

                        # Check if the file name matches the provided pattern.
                        if arg_file_name:
                            if not fnmatch.fnmatch(file_name, arg_file_name):
                                #print_warning("Skip, file \"{0}\" doesn't match the file name pattern".format(file_path))
                                continue

                        # Check if the file type matches the provided pattern.
                        if arg_file_type:
                            if arg_file_type not in File(file_path).type:
                                #print_warning("Skip, file \"{0}\" doesn't match the file type".format(file_path))
                                continue

                        # Check if file exceeds maximum size limit.
                        if arg_file_size:
                            # Obtain file size.
                            if os.path.getsize(file_path) > arg_file_size:
                                print_warning("Skip, file \"{0}\" is too big".format(file_path))
                                continue

                        file_obj = File(file_path)

                        # Add file.
                        add_file(file_obj, arg_tags)
            else:
                print_error("You specified an invalid folder: {0}".format(arg_folder))
        # Otherwise we try to store the currently opened file, if there is any.
        else:
            if __sessions__.is_set():
                if __sessions__.current.file.size == 0:
                    print_warning("Skip, file \"{0}\" appears to be empty".format(__sessions__.current.file.name))
                    return False

                # Add file.
                if add_file(__sessions__.current.file, arg_tags):
                    # Open session to the new file.
                    self.cmd_open(*[__sessions__.current.file.sha256])
            else:
                print_error("No session opened")

    ##
    # DELETE
    #
    # This commands deletes the currenlty opened file (only if it's stored in
    # the local repository) and removes the details from the database
    def cmd_delete(self, *args):
        if __sessions__.is_set():
            while True:
                choice = raw_input("Are you sure you want to delete this binary? Can't be reverted! [y/n] ")
                if choice == 'y':
                    break
                elif choice == 'n':
                    return

            rows = self.db.find('sha256', __sessions__.current.file.sha256)
            if rows:
                malware_id = rows[0].id
                if self.db.delete(malware_id):
                    print_success("File deleted")
                else:
                    print_error("Unable to delete file")

            os.remove(__sessions__.current.file.path)
            __sessions__.close()
        else:
            print_error("No session opened")

    ##
    # FIND
    #
    # This command is used to search for files in the database.
    def cmd_find(self, *args):
        def usage():
            print("usage: find [-h] [-t] <all|latest|name|type|mime|md5|sha256|tag|note> <value>")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--tags (-t)\tList tags")
            print("")

        try:
            opts, argv = getopt.getopt(args, 'ht', ['help', 'tags'])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        arg_list_tags = False

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-t', '--tags'):
                arg_list_tags = True

        # One of the most useful search terms is by tag. With the --tags
        # argument we first retrieve a list of existing tags and the count
        # of files associated with each of them.
        if arg_list_tags:
            # Retrieve list of tags.
            tags = self.db.list_tags()

            if tags:
                rows = []
                # For each tag, retrieve the count of files associated with it.
                for tag in tags:
                    count = len(self.db.find('tag', tag.tag))
                    rows.append([tag.tag, count])

                # Generate the table with the results.
                header = ['Tag', '# Entries']
                rows.sort(key=lambda x: x[1], reverse=True)
                print(table(header=header, rows=rows))
            else:
                print("No tags available")

            return

        # At this point, if there are no search terms specified, return.
        if len(args) == 0:
            usage()
            return

        # The first argument is the search term (or "key").
        key = args[0]
        if key != 'all' and key != 'latest':
            try:
                # The second argument is the search value.
                value = args[1]
            except IndexError:
                print_error("You need to include a search term.")
                return
        else:
            value = None

        # Search all the files matching the given parameters.
        items = self.db.find(key, value)
        if not items:
            return

        # Populate the list of search results.
        rows = []
        count = 1
        for item in items:
            tag = ', '.join([t.tag for t in item.tag if t.tag])
            row = [count, item.name, item.mime, item.md5, tag]
            if key == 'latest':
                row.append(item.created_at)

            rows.append(row)
            count += 1

        # Update find results in current session.
        __sessions__.find = items

        # Generate a table with the results.
        header = ['#', 'Name', 'Mime', 'MD5', 'Tags']
        if key == 'latest':
            header.append('Created At')

        print(table(header=header, rows=rows))

    ##
    # TAGS
    #
    # This command is used to modify the tags of the opened file.
    def cmd_tags(self, *args):
        def usage():
            print("usage: tags [-h] [-a=tags] [-d=tag]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--add (-a)\tAdd tags to the opened file (comma separated)")
            print("\t--delete (-d)\tDelete a tag from the opened file")
            print("")

        try:
            opts, argv = getopt.getopt(args, 'ha:d:', ['help', 'add=', 'delete='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        arg_add = None
        arg_delete = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-a', '--add'):
                arg_add = value
            elif opt in ('-d', '--delete'):
                arg_delete = value

        # This command requires a session to be opened.
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        # If no arguments are specified, there's not much to do.
        # However, it could make sense to also retrieve a list of existing
        # tags from this command, and not just from the "find" command alone.
        if not arg_add and not arg_delete:
            usage()
            return

        # TODO: handle situation where addition or deletion of a tag fail.

        if arg_add:
            # Add specified tags to the database's entry belonging to
            # the opened file.
            db = Database()
            db.add_tags(__sessions__.current.file.sha256, arg_add)
            print_info("Tags added to the currently opened file")

            # We refresh the opened session to update the attributes.
            # Namely, the list of tags returned by the "info" command
            # needs to be re-generated, or it wouldn't show the new tags
            # until the existing session is closed a new one is opened.
            print_info("Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

        if arg_delete:
            # Delete the tag from the database.
            Database().delete_tag(arg_delete)
            # Refresh the session so that the attributes of the file are
            # updated.
            print_info("Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

    ###
    # SESSION
    #
    # This command is used to list and switch across all the opened sessions.
    def cmd_sessions(self, *args):
        def usage():
            print("usage: sessions [-h] [-l] [-s=session]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--list (-l)\tList all existing sessions")
            print("\t--switch (-s)\tSwitch to the specified session")
            print("")

        try:
            opts, argv = getopt.getopt(args, 'hls:', ['help', 'list', 'switch='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        arg_list = False
        arg_switch = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-l', '--list'):
                arg_list = True
            elif opt in ('-s', '--switch'):
                arg_switch = int(value)

        if arg_list:
            if not __sessions__.sessions:
                print_info("There are no opened sessions")
                return

            rows = []
            for session in __sessions__.sessions:
                current = ''
                if session == __sessions__.current:
                    current = 'Yes'

                rows.append([
                    session.id,
                    session.file.name,
                    session.file.md5,
                    session.created_at,
                    current
                ])

            print_info("Opened Sessions:")
            print(table(header=['#', 'Name', 'MD5', 'Created At', 'Current'], rows=rows))
            return
        elif arg_switch:
            for session in __sessions__.sessions:
                if arg_switch == session.id:
                    __sessions__.switch(session)
                    return

            print_warning("The specified session ID doesn't seem to exist")
            return

        usage()

    ##
    # PROJECTS
    #
    # This command retrieves a list of all projects.
    # You can also switch to a different project.
    def cmd_projects(self, *args):
        def usage():
            print("usage: projects [-h] [-l] [-s=project]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--list (-l)\tList all existing projects")
            print("\t--switch (-s)\tSwitch to the specified project")
            print("")

        try:
            opts, argv = getopt.getopt(args, 'hls:', ['help', 'list', 'switch='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        arg_list = False
        arg_switch = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-l', '--list'):
                arg_list = True
            elif opt in ('-s', '--switch'):
                arg_switch = value

        projects_path = os.path.join(os.getcwd(), 'projects')

        if not os.path.exists(projects_path):
            print_info("The projects directory does not exist yet")
            return

        if arg_list:
            print_info("Projects Available:")

            rows = []
            for project in os.listdir(projects_path):
                project_path = os.path.join(projects_path, project)
                if os.path.isdir(project_path):
                    current = ''
                    if __project__.name and project == __project__.name:
                        current = 'Yes'
                    rows.append([project, time.ctime(os.path.getctime(project_path)), current])

            print(table(header=['Project Name', 'Creation Time', 'Current'], rows=rows))
            return
        elif arg_switch:
            if __sessions__.is_set():
                __sessions__.close()
                print_info("Closed opened session")

            __project__.open(arg_switch)
            print_info("Switched to project {0}".format(bold(arg_switch)))

            # Need to re-initialize the Database to open the new SQLite file.
            self.db = Database()
            return

        usage()

    ##
    # EXPORT
    #
    # This command will export the current session to file or zip.
    def cmd_export(self, *args):
        def usage():
            print("usage: export [-h] [-z] <path or archive name>")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--zip (-z)\tExport session in a zip archive")
            print("")

        try:
            opts, argv = getopt.getopt(args, 'hz', ['help', 'zip'])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        arg_zip = False

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-z', '--zip'):
                arg_zip = True
                
        # This command requires a session to be opened.
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        # Check for valid export path.
        if len(args) ==0:
            usage()
            return

        # TODO: having for one a folder and for the other a full
        # target path can be confusing. We should perhaps standardize this.

        # Abort if the specified path already exists.
        if os.path.isfile(argv[0]):
            print_error("File at path \"{0}\" already exists, abort".format(argv[0]))
            return

        # If the argument chosed so, archive the file when exporting it.
        # TODO: perhaps add an option to use a password for the archive
        # and default it to "infected".
        if arg_zip:
            try:
                with ZipFile(argv[0], 'w') as export_zip:
                    export_zip.write(__sessions__.current.file.path, arcname=__sessions__.current.file.name)
            except IOError as e:
                print_error("Unable to export file: {0}".format(e))
            else:
                print_info("File archived and exported to {0}".format(argv[0]))
        # Otherwise just dump it to the given directory.
        else:
            # XXX: Export file with the original file name.
            store_path = os.path.join(argv[0], __sessions__.current.file.name)

            try:
                shutil.copyfile(__sessions__.current.file.path, store_path)
            except IOError as e:
                print_error("Unable to export file: {0}".format(e))
            else:
                print_info("File exported to {0}".format(store_path))
