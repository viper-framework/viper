# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
from os.path import expanduser
import logging

from viper.core.config import Config
from viper.core.logger import init_logger

log = logging.getLogger('viper')

cfg = Config()


class Project(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.base_path = None
        if cfg.paths.storage_path:
            self.path = cfg.paths.storage_path
            self.base_path = cfg.paths.storage_path
        else:
            self.path = os.path.join(expanduser("~"), '.viper')
            self.base_path = os.path.join(expanduser("~"), '.viper')

        if not os.path.exists(self.path):
            os.makedirs(self.path)

        # initalize default log settings
        log_file = os.path.join(self.base_path, "viper.log")
        debug_log = False

        if hasattr(cfg, 'logging'):
            if hasattr(cfg.logging, 'log_file') and cfg.logging.log_file:
                log_file = cfg.logging.log_file

            if hasattr(cfg.logging, 'debug'):
                debug_log = cfg.logging.debug

        init_logger(log_file_path=log_file, debug=debug_log)
        log.debug("logger initiated")

    def open(self, name):
        if not os.path.exists(self.base_path):
            raise Exception("The local storage folder does not exist at path {}".format(self.base_path))

        if name == 'default':
            path = self.base_path
        else:
            path = os.path.join(self.base_path, 'projects', name)
            if not os.path.exists(path):
                os.makedirs(path)

        self.name = name
        self.path = path

    def get_path(self):
        if self.path and os.path.exists(self.path):
            return self.path
        else:
            return self.path

    def get_projects_path(self):
        return os.path.join(self.base_path, 'projects')


__project__ = Project()


def get_project_list(exclude_default=False):
    """get_project_list - get list of all projects"""
    projects_path = __project__.get_projects_path()
    project_list = []
    if os.path.exists(projects_path):
        for project in os.listdir(projects_path):
            project_path = os.path.join(projects_path, project)
            if os.path.isdir(project_path):
                project_list.append(project)

    if exclude_default:
        pass
    else:
        project_list.append("default")

    return project_list
