# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import json

from viper.common.abstracts import Command
from viper.common.colors import bold
from viper.core.session import __sessions__
from viper.core.database import Database


class Analysis(Command):
    """
    This command allows you to view the stored output from modules that have been run
    with the currently opened file.
    """
    cmd = "analysis"
    description = "View the stored analysis"

    def __init__(self):
        super(Analysis, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action='store_true',
                           help="List all module results available for the current file")
        group.add_argument('-v', '--view', metavar='ANALYSIS ID', type=int, help="View the specified analysis")
        group.add_argument('-d', '--delete', metavar='ANALYSIS ID', type=int, help="Delete an existing analysis")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            return

        db = Database()

        # check if the file is already stores, otherwise exit
        malware = db.find(key='sha256', value=__sessions__.current.file.sha256)
        if not malware:
            self.log('error', "The opened file doesn't appear to be in the database, have you stored it yet?")
            return

        if args.list:
            # Retrieve all analysis for the currently opened file.

            analysis_list = malware[0].analysis
            if not analysis_list:
                self.log('info', "No analysis available for this file yet")
                return

            # Populate table rows.
            rows = [[analysis.id, analysis.cmd_line, analysis.stored_at] for analysis in analysis_list]

            # Display list of existing results.
            self.log('table', dict(header=['ID', 'Cmd Line', 'Saved On (UTC)'], rows=rows))

        elif args.view:
            # Retrieve analysis wth the specified ID and print it.
            result = db.get_analysis(args.view)
            if result:
                self.log('info', bold('Cmd Line: ') + result.cmd_line)
                for line in json.loads(result.results):
                    self.log(line['type'], line['data'])
            else:
                self.log('info', "There is no analysis with ID {0}".format(args.view))
