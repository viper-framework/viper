# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import time
from os.path import expanduser

from viper.common.abstracts import Command
from viper.common.colors import bold
from viper.core.database import Database
from viper.core.session import __sessions__
from viper.core.project import __project__

class Projects(Command):
    ##
    # PROJECTS
    #
    # This command retrieves a list of all projects.
    # You can also switch to a different project.
    cmd = "projects"
    description = "List or switch existing projects"

    def __init__(self):
        super(Projects, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action='store_true', help="List all existing projects")
        group.add_argument('-s', '--switch', metavar='PROJECT NAME', help="Switch to the specified project")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if cfg.get('paths').storage_path:
            base_path = cfg.get('paths').storage_path
        else:
            base_path = os.path.join(expanduser("~"), '.viper')

        projects_path = os.path.join(base_path, 'projects')

        if args.list:
            if not os.path.exists(projects_path):
                self.log('info', "The projects directory does not exist yet")
                return

            self.log('info', "Projects Available:")

            rows = []
            for project in os.listdir(projects_path):
                project_path = os.path.join(projects_path, project)
                if os.path.isdir(project_path):
                    current = ''
                    if __project__.name and project == __project__.name:
                        current = 'Yes'
                    rows.append([project, time.ctime(os.path.getctime(project_path)), current])

            self.log('table', dict(header=['Project Name', 'Creation Time', 'Current'], rows=rows))
        elif args.switch:
            if __sessions__.is_set():
                __sessions__.close()
                self.log('info', "Closed opened session")

            __project__.open(args.switch)
            self.log('info', "Switched to project {0}".format(bold(args.switch)))

            # Need to re-initialize the Database to open the new SQLite file.
            Database().__init__()
        else:
            self.log('info', self.parser.print_usage())
