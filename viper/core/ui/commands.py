# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import argparse
import os
import time
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
        parser = argparse.ArgumentParser(prog="open", description="Open a file", epilog="You can also specify a MD5 or SHA256 hash to a previously stored file in order to open a session on it.")
        group = parser.add_mutually_exclusive_group()
        group.add_argument('-f', '--file', action="store_true", help="target is a file")
        group.add_argument('-u', '--url', action="store_true", help="target is a URL")
        group.add_argument('-l', '--last', action="store_true", help="target is the entry number from the last find command's results")
        parser.add_argument('-t', '--tor', action="store_true", help="Download the file through Tor")
        parser.add_argument("value", metavar='Path, URL, hash or ID', nargs='*', help="Target to open. Hash can be md5 or sha256. ID has to be from the last search.")

        try:
            args = parser.parse_args(args)
        except:
            return

        target = " ".join(args.value)

        if not args.last and target is None:
            parser.print_usage()
            return

        # If it's a file path, open a session on it.
        if args.file:
            target = os.path.expanduser(target)

            if not os.path.exists(target) or not os.path.isfile(target):
                print_error("File not found: {0}".format(target))
                return

            __sessions__.new(target)
        # If it's a URL, download it and open a session on the temporary file.
        elif args.url:
            data = download(url=target, tor=args.tor)

            if data:
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.write(data)
                tmp.close()

                __sessions__.new(tmp.name)
        # Try to open the specified file from the list of results from
        # the last find command.
        elif args.last:
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
            target = target.strip().lower()

            if len(target) == 32:
                key = 'md5'
            elif len(target) == 64:
                key = 'sha256'
            else:
                parser.print_usage()
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
        parser = argparse.ArgumentParser(prog="notes", description="Show information on the opened file")
        group = parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action="store_true", help="List all notes available for the current file")
        group.add_argument('-a', '--add', action="store_true", help="Add a new note to the current file")
        group.add_argument('-v', '--view', metavar='note_id', type=int, help="View the specified note")
        group.add_argument('-e', '--edit', metavar='note_id', type=int, help="Edit an existing note")
        group.add_argument('-d', '--delete', metavar='note_id', type=int, help="Delete an existing note")

        try:
            args = parser.parse_args(args)
        except:
            return

        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if args.list:
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
            rows = [[note.id, note.title] for note in notes]

            # Display list of existing notes.
            print(table(header=['ID', 'Title'], rows=rows))

        elif args.add:
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

        elif args.view:
            # Retrieve note wth the specified ID and print it.
            note = Database().get_note(args.view)
            if note:
                print_info(bold('Title: ') + note.title)
                print_info(bold('Body:'))
                print(note.body)
            else:
                print_info("There is no note with ID {0}".format(args.view))

        elif args.edit:
            # Retrieve note with the specified ID.
            note = Database().get_note(args.edit)
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
                Database().edit_note(args.edit, body)
                # Remove the temporary file.
                os.remove(tmp.name)

                print_info("Updated note with ID {0}".format(args.edit))

        elif args.delete:
            # Delete the note with the specified ID.
            Database().delete_note(args.delete)
        else:
            parser.print_usage()

    ##
    # STORE
    #
    # This command stores the opened file in the local repository and tries
    # to store details in the database.
    def cmd_store(self, *args):
        parser = argparse.ArgumentParser(prog="store", description="Store the opened file to the local repository")
        parser.add_argument('-d', '--delete', action="store_true", help="Delete the original file")
        parser.add_argument('-f', '--folder', type=str, nargs='+', help="Specify a folder to import")
        parser.add_argument('-s', '--file-size', type=int, help="Specify a maximum file size")
        parser.add_argument('-y', '--file-type', type=str, help="Specify a file type pattern")
        parser.add_argument('-n', '--file-name', type=str, help="Specify a file name pattern")
        parser.add_argument('-t', '--tags', type=str, nargs='+', help="Specify a list of comma-separated tags")

        try:
            args = parser.parse_args(args)
        except:
            return

        if args.folder is not None:
            # Allows to have spaces in the path.
            args.folder = " ".join(args.folder)

        if args.tags is not None:
            # Remove the spaces in the list of tags
            args.tags = "".join(args.tags)

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
            if args.delete:
                try:
                    os.unlink(obj.path)
                except Exception as e:
                    print_warning("Failed deleting file: {0}".format(e))

            return True

        # If the user specified the --folder flag, we walk recursively and try
        # to add all contained files to the local repository.
        # This is note going to open a new session.
        # TODO: perhaps disable or make recursion optional?
        if args.folder is not None:
            # Check if the specified folder is valid.
            if os.path.isdir(args.folder):
                # Walk through the folder and subfolders.
                for dir_name, dir_names, file_names in os.walk(args.folder):
                    # Add each collected file.
                    for file_name in file_names:
                        file_path = os.path.join(dir_name, file_name)

                        if not os.path.exists(file_path):
                            continue
                        # Check if file is not zero.
                        if not os.path.getsize(file_path) > 0:
                            continue

                        # Check if the file name matches the provided pattern.
                        if args.file_name:
                            if not fnmatch.fnmatch(file_name, args.file_name):
                                # print_warning("Skip, file \"{0}\" doesn't match the file name pattern".format(file_path))
                                continue

                        # Check if the file type matches the provided pattern.
                        if args.file_type:
                            if args.file_type not in File(file_path).type:
                                # print_warning("Skip, file \"{0}\" doesn't match the file type".format(file_path))
                                continue

                        # Check if file exceeds maximum size limit.
                        if args.file_size:
                            # Obtain file size.
                            if os.path.getsize(file_path) > args.file_size:
                                print_warning("Skip, file \"{0}\" is too big".format(file_path))
                                continue

                        file_obj = File(file_path)

                        # Add file.
                        add_file(file_obj, args.tags)
            else:
                print_error("You specified an invalid folder: {0}".format(args.folder))
        # Otherwise we try to store the currently opened file, if there is any.
        else:
            if __sessions__.is_set():
                if __sessions__.current.file.size == 0:
                    print_warning("Skip, file \"{0}\" appears to be empty".format(__sessions__.current.file.name))
                    return False

                # Add file.
                if add_file(__sessions__.current.file, args.tags):
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
        parser = argparse.ArgumentParser(prog="find", description="Find a file")
        group = parser.add_mutually_exclusive_group()
        group.add_argument('-t', '--tags', action="store_true", help="List available tags and quit")
        group.add_argument('type', nargs='?', choices=["all", "latest", "name", "type", "mime", "md5", "sha256", "tag", "note"], help="Where to search.")
        parser.add_argument("value", nargs='?', help="String to search.")
        try:
            args = parser.parse_args(args)
        except:
            return

        # One of the most useful search terms is by tag. With the --tags
        # argument we first retrieve a list of existing tags and the count
        # of files associated with each of them.
        if args.tags:
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
        if args.type is None:
            parser.print_usage()
            return

        key = args.type
        if key != 'all' and key != 'latest':
            try:
                # The second argument is the search value.
                value = args.value
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
        parser = argparse.ArgumentParser(prog="tags", description="Modify tags of the opened file")
        parser.add_argument('-a', '--add', help="Add tags to the opened file (comma separated)")
        parser.add_argument('-d', '--delete', help="Delete a tag from the opened file")
        try:
            args = parser.parse_args(args)
        except:
            return

        # This command requires a session to be opened.
        if not __sessions__.is_set():
            print_error("No session opened")
            parser.print_usage()
            return

        # If no arguments are specified, there's not much to do.
        # However, it could make sense to also retrieve a list of existing
        # tags from this command, and not just from the "find" command alone.
        if args.add is None and args.delete is None:
            parser.print_usage()
            return

        # TODO: handle situation where addition or deletion of a tag fail.

        if args.add:
            # Add specified tags to the database's entry belonging to
            # the opened file.
            db = Database()
            db.add_tags(__sessions__.current.file.sha256, args.add)
            print_info("Tags added to the currently opened file")

            # We refresh the opened session to update the attributes.
            # Namely, the list of tags returned by the "info" command
            # needs to be re-generated, or it wouldn't show the new tags
            # until the existing session is closed a new one is opened.
            print_info("Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

        if args.delete:
            # Delete the tag from the database.
            Database().delete_tag(args.delete)
            # Refresh the session so that the attributes of the file are
            # updated.
            print_info("Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

    ###
    # SESSION
    #
    # This command is used to list and switch across all the opened sessions.
    def cmd_sessions(self, *args):
        parser = argparse.ArgumentParser(prog="sessions", description="Open a file", epilog="List or switch sessions")
        group = parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action="store_true", help="List all existing sessions")
        group.add_argument('-s', '--switch', type=int, help="Switch to the specified session")

        try:
            args = parser.parse_args(args)
        except:
            return

        if args.list:
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
        elif args.switch:
            for session in __sessions__.sessions:
                if args.switch == session.id:
                    __sessions__.switch(session)
                    return

            print_warning("The specified session ID doesn't seem to exist")
        else:
            parser.print_usage()

    ##
    # PROJECTS
    #
    # This command retrieves a list of all projects.
    # You can also switch to a different project.
    def cmd_projects(self, *args):
        parser = argparse.ArgumentParser(prog="projects", description="Open a file", epilog="List or switch existing projects")
        group = parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action="store_true", help="List all existing projects")
        group.add_argument('-s', '--switch', metavar='project_name', help="Switch to the specified project")

        try:
            args = parser.parse_args(args)
        except:
            return

        projects_path = os.path.join(os.getcwd(), 'projects')

        if not os.path.exists(projects_path):
            print_info("The projects directory does not exist yet")
            return

        if args.list:
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
        elif args.switch:
            if __sessions__.is_set():
                __sessions__.close()
                print_info("Closed opened session")

            __project__.open(args.switch)
            print_info("Switched to project {0}".format(bold(args.switch)))

            # Need to re-initialize the Database to open the new SQLite file.
            self.db = Database()
        else:
            parser.print_usage()

    ##
    # EXPORT
    #
    # This command will export the current session to file or zip.
    def cmd_export(self, *args):
        parser = argparse.ArgumentParser(prog="export", description="Export the current session to file or zip")
        parser.add_argument('-z', '--zip', action="store_true", help="Export session in a zip archive")
        parser.add_argument('value', help="path or archive name")

        try:
            args = parser.parse_args(args)
        except:
            return

        # This command requires a session to be opened.
        if not __sessions__.is_set():
            print_error("No session opened")
            parser.print_usage()
            return

        # Check for valid export path.
        if args.path is None:
            parser.print_usage()
            return

        # TODO: having for one a folder and for the other a full
        # target path can be confusing. We should perhaps standardize this.

        # Abort if the specified path already exists.
        if os.path.isfile(args.value):
            print_error("File at path \"{0}\" already exists, abort".format(args.value))
            return

        # If the argument chosed so, archive the file when exporting it.
        # TODO: perhaps add an option to use a password for the archive
        # and default it to "infected".
        if args.zip:
            try:
                with ZipFile(args.value, 'w') as export_zip:
                    export_zip.write(__sessions__.current.file.path, arcname=__sessions__.current.file.name)
            except IOError as e:
                print_error("Unable to export file: {0}".format(e))
            else:
                print_info("File archived and exported to {0}".format(args.value))
        # Otherwise just dump it to the given directory.
        else:
            # XXX: Export file with the original file name.
            store_path = os.path.join(args.value, __sessions__.current.file.name)

            try:
                shutil.copyfile(__sessions__.current.file.path, store_path)
            except IOError as e:
                print_error("Unable to export file: {0}".format(e))
            else:
                print_info("File exported to {0}".format(store_path))
