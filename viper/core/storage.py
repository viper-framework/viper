# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import shutil

from viper.common.out import print_warning, print_error, print_info
from viper.core.project import __project__
from viper.common.constants import VIPER_ROOT
from viper.common.constants import VIPER_RULES_DIST_DIR


def store_sample(file_object):
    sha256 = file_object.sha256

    if not sha256:
        print_error("No hash")
        return None

    folder = os.path.join(
        __project__.get_path(),
        'binaries',
        sha256[0],
        sha256[1],
        sha256[2],
        sha256[3]
    )

    if not os.path.exists(folder):
        os.makedirs(folder, 0o750)

    file_path = os.path.join(folder, sha256)

    if not os.path.exists(file_path):
        with open(file_path, 'wb') as stored:
            for chunk in file_object.get_chunks():
                stored.write(chunk)
    else:
        print_warning("File exists already")
        return None

    return file_path


def get_sample_path(sha256):
    path = os.path.join(
        __project__.get_path(),
        'binaries',
        sha256[0],
        sha256[1],
        sha256[2],
        sha256[3],
        sha256
    )

    if not os.path.exists(path):
        return None

    return path


def check_and_deploy_yara_rules():
    """Yara: check whether rule path exist - if not copy default set of rules to directory"""
    yara_rules_path = os.path.join(__project__.base_path, "yara")
    if os.path.exists(yara_rules_path):
        print_info("Using Yara rules from directory: {}".format(yara_rules_path))
    else:
        # Prio 1: rules if Viper was installed with pip
        yara_path_setup_utils = os.path.join(VIPER_ROOT, VIPER_RULES_DIST_DIR)

        # Prio 2: rules if Viper was checkout from repo
        yara_path_repo = os.path.join(VIPER_ROOT, "data", "yara")

        if os.path.exists(yara_path_setup_utils):
            print_warning("Yara rule directory not found - copying default "
                          "rules ({}) to: {}".format(yara_path_setup_utils, yara_rules_path))

            shutil.copytree(yara_path_setup_utils, yara_rules_path)
        elif os.path.exists(yara_path_repo):
            print_warning("Yara rule directory not found - copying default "
                          "rules ({}) to: {}".format(yara_path_repo, yara_rules_path))
            shutil.copytree(yara_path_repo, yara_rules_path)
        else:
            print_error("No default Yara rules found")
