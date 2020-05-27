# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import time
import shutil
from os.path import expanduser

from viper.common.abstracts import Command
from viper.common.colors import bold
from viper.core.database import Database
from viper.core.session import __sessions__
from viper.core.project import __project__
from viper.core.config import __config__


class Projects(Command):
    """
    This command retrieves a list of all projects.
    You can also switch to a different project.
    """
    cmd = "projects"
    description = "List or switch existing projects"

    def __init__(self):
        super(Projects, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument("-l", "--list", action="store_true", help="List all existing projects")
        group.add_argument("-s", "--switch", metavar="PROJECT NAME", help="Switch to the specified project")
        group.add_argument("-c", "--close", action="store_true", help="Close the currently opened project")
        group.add_argument("-d", "--delete", metavar="PROJECT NAME", help="Delete the specified project")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if __config__.get("paths").storage_path:
            base_path = __config__.get("paths").storage_path
        else:
            base_path = os.path.join(expanduser("~"), ".viper")

        projects_path = os.path.join(base_path, "projects")

        if args.list:
            if not os.path.exists(projects_path):
                self.log("info", "No projects have been created yet")
                return

            self.log("info", "Projects Available:")

            rows = []
            for project in os.listdir(projects_path):
                project_path = os.path.join(projects_path, project)
                if os.path.isdir(project_path):
                    current = ""
                    if __project__.name and project == __project__.name:
                        current = "Yes"
                    rows.append([project, time.ctime(os.path.getctime(project_path)), current])

            self.log("table", dict(header=["Project Name", "Creation Time", "Current"], rows=rows))
        elif args.switch:
            if __sessions__.is_set():
                __sessions__.close()
                self.log("info", "Closed opened session")

            __project__.open(args.switch)
            self.log("info", "Switched to project {0}".format(bold(args.switch)))

            # Need to re-initialize the Database to open the new SQLite file.
            Database().__init__()
        elif args.close:
            if __project__.name != "default":
                if __sessions__.is_set():
                    __sessions__.close()

                __project__.close()
        elif args.delete:
            project_to_delete = args.delete
            if project_to_delete == "default":
                self.log("error", "You can't delete the \"default\" project")
                return

            # If it"s the currently opened project, we close it.
            if project_to_delete == __project__.name:
                # We close any opened session.
                if __sessions__.is_set():
                    __sessions__.close()

                __project__.close()

            project_path = os.path.join(projects_path, project_to_delete)
            if not os.path.exists(project_path):
                self.log("error", "The folder for project \"{}\" does not seem to exist".format(project_to_delete))
                return

            self.log("info", "You asked to delete project with name \"{}\" located at \"{}\"".format(project_to_delete, project_path))

            confirm = input("Are you sure you want to delete the project? You will permanently delete all associated files! [y/N] ")
            if confirm.lower() != "y":
                return

            try:
                shutil.rmtree(project_path)
            except Exception as e:
                self.log("error", "Something failed while trying to delete folder: {}".format(e))
                return

            self.log("info", "Project \"{}\" was delete successfully".format(project_to_delete))
        else:
            self.log("info", self.parser.print_usage())
