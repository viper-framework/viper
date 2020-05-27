# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import tempfile

from viper.common.abstracts import Command
from viper.common.colors import bold
from viper.core.database import Database
from viper.core.session import __sessions__


class Notes(Command):
    """
    This command allows you to view, add, modify and delete notes associated
    with the currently opened file or project.
    """
    cmd = "notes"
    description = "View, add and edit notes on the opened file or project"

    def __init__(self):
        super(Notes, self).__init__()
        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action='store_true', help="List all notes available for the current file or project")
        group.add_argument('-a', '--add', action='store_true', help="Add a new note to the current file or project")
        group.add_argument('-v', '--view', metavar='NOTE ID', type=int, help="View the specified note")
        group.add_argument('-e', '--edit', metavar='NOTE ID', type=int, help="Edit an existing note")
        group.add_argument('-d', '--delete', metavar='NOTE ID', type=int, help="Delete an existing note")
        self.parser.add_argument('-p', '--project', action='store_true', help="Use project notes instead of notes being tied to a file")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        db = Database()
        malware = None
        if __sessions__.is_set() and not args.project:
            malware = db.find(key='sha256', value=__sessions__.current.file.sha256)
            if not malware:
                self.log('error', "The opened file doesn't appear to be in the database, have you stored it yet?")

        if args.list:
            # Retrieve all notes for the currently opened file.
            notes = malware[0].note if malware is not None else db.list_notes()
            if not notes:
                self.log('info', "No notes available for this file or project yet")
                return

            # Populate table rows.
            rows = [[note.id, note.title] for note in notes]

            # Display list of existing notes.
            self.log('table', dict(header=['ID', 'Title'], rows=rows))

        elif args.add:
            title = input("Enter a title for the new note: ")

            # Create a new temporary file.
            with tempfile.NamedTemporaryFile(mode='w+') as tmp:
                # Open the temporary file with the default editor, or with nano.
                os.system('"${EDITOR:-nano}" ' + tmp.name)
                # Once the user is done editing, we need to read the content and
                # store it in the database.
                body = tmp.read()
                if args.project or not __sessions__.is_set():
                    db.add_note(None, title, body)
                    self.log('info', 'New note with title "{0}" added to the current project'.format(bold(title)))
                else:
                    db.add_note(__sessions__.current.file.sha256, title, body)
                    self.log('info', 'New note with title "{0}" added to the current file'.format(bold(title)))

        elif args.view:
            # Retrieve note wth the specified ID and print it.
            note = db.get_note(args.view)
            if note:
                self.log('info', bold('Title: ') + note.title)
                if isinstance(note.body, bytes):
                    # OLD: Old style, the content is stored as bytes
                    # This is fixed when the user edits the old note.
                    body = note.body.decode()
                else:
                    body = note.body
                self.log('info', '{}\n{}'.format(bold('Body:'), body))
            else:
                self.log('info', "There is no note with ID {0}".format(args.view))

        elif args.edit:
            # Retrieve note with the specified ID.
            note = db.get_note(args.edit)
            if note:
                # Create a new temporary file.
                with tempfile.NamedTemporaryFile(mode='w+') as tmp:
                    # Write the old body to the temporary file.
                    if isinstance(note.body, bytes):
                        # OLD: Old style, the content is stored as bytes
                        body = note.body.decode()
                    else:
                        body = note.body
                    tmp.write(body)
                    tmp.flush()
                    tmp.seek(0)
                    # Open the old body with the text editor.
                    os.system('"${EDITOR:-nano}" ' + tmp.name)
                    # Read the new body from the temporary file.
                    body = tmp.read()
                    # Update the note entry with the new body.
                    db.edit_note(args.edit, body)

                self.log('info', "Updated note with ID {0}".format(args.edit))

        elif args.delete:
            # Delete the note with the specified ID.
            db.delete_note(args.delete)
        else:
            self.parser.print_usage()
