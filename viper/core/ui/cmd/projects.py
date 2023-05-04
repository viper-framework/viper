# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import shutil
import time
from os.path import expanduser
from typing import Any

from viper.common.abstracts import Command
from viper.core.config import cfg
from viper.core.database import Database
from viper.core.projects import project
from viper.core.sessions import sessions


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
        group.add_argument(
            "-l", "--list", action="store_true", help="List all existing projects"
        )
        group.add_argument(
            "-s",
            "--switch",
            metavar="PROJECT NAME",
            help="Switch to the specified project",
        )
        group.add_argument(
            "-c",
            "--close",
            action="store_true",
            help="Close the currently open project",
        )
        group.add_argument(
            "-d",
            "--delete",
            metavar="PROJECT NAME",
            help="Delete the specified project",
        )

    def run(self, *args: Any):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if cfg.get("paths").storage_path:
            base_path = cfg.get("paths").storage_path
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
                    if project.name and project == project.name:
                        current = "Yes"
                    rows.append(
                        [project, time.ctime(os.path.getctime(project_path)), current]
                    )

            self.log(
                "table",
                dict(header=["Project Name", "Creation Time", "Current"], rows=rows),
            )
        elif args.switch:
            db = Database()
            if not db.supports_projects:
                self.log(
                    "info", "The database type you are using does not support projects"
                )
                return

            if sessions.is_set():
                sessions.close()
                self.log("info", "Closed open session")

            project.open(args.switch)
            self.log("info", f"Switched to project [bold]{args.switch}[/bold]")

            # Need to re-initialize the Database to open the new SQLite file.
            Database().__init__()
        elif args.close:
            if project.name != "default":
                if sessions.is_set():
                    sessions.close()

                project.close()
        elif args.delete:
            project_to_delete = args.delete
            if project_to_delete == "default":
                self.log("error", 'You can\'t delete the "default" project')
                return

            # If it's the currently open project, we close it.
            if project_to_delete == project.name:
                # We close any open session.
                if sessions.is_set():
                    sessions.close()

                project.close()

            project_path = os.path.join(projects_path, project_to_delete)
            if not os.path.exists(project_path):
                self.log(
                    "error",
                    f'The folder for project "{project_to_delete}" does not seem to exist',
                )
                return

            self.log(
                "info",
                f'You asked to delete project with name "{project_to_delete}" located at {project_path}',
            )

            confirm = input(
                "Are you sure you want to delete the project? You will permanently delete all associated files! [y/N] "
            )
            if confirm.lower() != "y":
                return

            try:
                shutil.rmtree(project_path)
            except Exception as e:
                self.log(
                    "error",
                    f"Something failed while trying to delete folder: {e}",
                )
                return

            self.log(
                "success",
                f'Project "{project_to_delete}" was delete successfully',
            )
        else:
            self.log("info", self.parser.print_usage())
