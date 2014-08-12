# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import hashlib

try:
    import magic
except ImportError:
    pass

# Taken from the Python Cookbook.
def path_split_all(path):
    allparts = []
    while 1:
        parts = os.path.split(path)
        if parts[0] == path:
            allparts.insert(0, parts[0])
            break
        elif parts[1] == path:
            allparts.insert(0, parts[1])
            break
        else:
            path = parts[0]
            allparts.insert(0, parts[1])

    return allparts

# The following couple of functions are redundant.
# TODO: find a way to better integrate these generic methods
# with the ones available in the File class.
def get_type(data):
    try:
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(data)
    except:
        try:
            file_type = magic.from_buffer(data)
        except:
            return ''
    finally:
        try:
            ms.close()
        except:
            pass

    return file_type

def get_md5(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()