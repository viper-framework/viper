# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import json 
from viper.common.abstracts import Command
from viper.core.database import Database, Malware
from viper.core.storage import get_sample_path
from viper.core.session import __sessions__
from viper.common.colors import cyan, yellow, red, green, bold, italic


class Report(Command):
    """
    This command is used to generate a report of the analysis or notes associated with Malware..
    """
    cmd = "report"
    description = "Report on the analysis or notes for Malware."

    def __init__(self):
        super(Report, self).__init__()
        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-a', '--analysis', action='store_true', help="View all analysis")
        group.add_argument('-n', '--notes', action='store_true', help="View all notes")
        self.parser.add_argument('-r', '--recursive', action='store_true', help="Add the same details for all children to the report")


    def print_header(self, header):
        print('\n' + '-'*80)
        print(bold(header) + " report for '{}'".format(__sessions__.current.file.path))
        print('-'*80)

        
    def print_analysis(self, malware_sha256):
        db = Database()
        malware = db.find(key='sha256', value=malware_sha256)
        analysis_list = malware[0].analysis
        if analysis_list:
            for analysis in analysis_list:
                result = db.get_analysis(analysis.id)
                self.log('info', bold('Cmd Line: ') + result.cmd_line)
                self.log('info', bold('Saved on (UTC): ') + str(result.stored_at))
                for line in json.loads(result.results):
                    if line['type'] != 'error':
                        self.log(line['type'], line['data'] )
                print()
        else:
            self.log('info', "No analysis available for this file yet.")

    
    def print_notes(self, malware_sha256):
        db = Database()
        malware = db.find(key='sha256', value=malware_sha256)
        notes = malware[0].note
        if notes:
            for note in notes:
                print(bold(note.title))
                print(italic(note.body))
        else:
            self.log('info', "No notes available for this file yet.")


    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            self.parser.print_usage()
            return

        if not (args.analysis or args.notes):
            self.parser.print_usage()
            return

        db = Database()
        child_ids = db.get_children(__sessions__.current.file.sha256, recursive=True)
        children = [ db.Session().query(Malware).get(child_id) for child_id in child_ids ]
        
        if args.analysis:
            self.print_header('Analysis')
            self.print_analysis(__sessions__.current.file.sha256)        
            if args.recursive:
                for child in children:
                    print(bold("Child: {0}' [{1}]".format(child.name, child.sha256)))
                    self.print_analysis(child.sha256)
        elif args.notes:
            self.print_header('Notes')
            self.print_notes(__sessions__.current.file.sha256)
            if args.recursive:
                for child in children:
                    print(bold("\nChild: {0}' [{1}]".format(child.name, child.sha256)))
                    self.print_notes(child.sha256)