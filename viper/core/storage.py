# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

from viper.common.out import print_warning, print_error
from viper.core.project import __project__

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
