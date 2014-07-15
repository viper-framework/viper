# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import hashlib
from StringIO import StringIO
from zipfile import ZipFile, ZIP_STORED

from viper.common.out import *
from viper.common.network import download
from viper.common.objects import File
from viper.common.utils import path_split_all

url = 'https://github.com/botherder/viper/archive/master.zip'

# TODO: this is a first draft, needs more work.
def main():
    master = download(url)
    zip_data = StringIO()
    zip_data.write(master)

    zip_file = ZipFile(zip_data, 'r')

    names = zip_file.namelist()
    base_dir = names[0]

    for name in names[1:]:
        name_parts = path_split_all(name)
        name_data = zip_file.read(name)
        name_data_md5 = hashlib.md5(name_data).hexdigest()
        local_file_path = os.path.join(*name_parts[1:])

        if os.path.isdir(local_file_path):
            continue

        exists = False
        if os.path.exists(local_file_path):
            exists = True
            local_file = File(local_file_path)
            if local_file.md5 == name_data_md5:
                print_info("{0} up-to-date".format(local_file_path))
                continue

        new_local = open(local_file_path, 'w')
        new_local.write(name_data)
        new_local.close()

        if exists:
            print_success("File {0} has been updated".format(local_file_path))
        else:
            print_success("New file {0} has been created".format(local_file_path))

if __name__ == '__main__':
    main()
