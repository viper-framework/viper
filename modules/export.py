# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
from zipfile import ZipFile
import shutil
import subprocess
import getopt


from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

# TODO: Should probably split the different parsing capabilities in
# separate options and have a --all to run them all.

class Exporte(Module):
    cmd = 'export'
    description = 'Export object from Database'
    authors = ['Kevin Breen']

    def run(self):
        def usage():
            print("usage: export [-hzp] <path>")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--zip (-z)\tAdd to Zip Archive")
            print("\t--pass (-p)\tAdd to Zip Archive With Password")
            print("")
            print("Adding a password to the archive requires zip or 7zip")
            print("apt-get install zip or p7zip-full")

        def compress(password, export_path):

            if password is not None:
                # Adding a password requires an external call to zip or 7zip
                # to avoid getting the directorys included in the zip structure
                # temp switch the working dir
                
                #get current so we can switch back later
                prev_cwd = os.getcwd()
                # get the new dir from the session file path
                working_dir = os.path.dirname(__session__.file.path)
                filename = os.path.basename(__session__.file.path)
                
                # fix for relative paths
                if export_path.startswith('../'):
                    save_path = os.path.join(prev_cwd, export_path)
                else:
                    save_path = export_path
                    
                # Switch to the new dir
                os.chdir(working_dir)
                # try 7 zip compression method
                print_info("Using 7zip to create")
                try:
                    rc = subprocess.call(['7z', 'a', '-p'+password, '-y', save_path] + [filename], shell=False)
                    os.chdir(prev_cwd)
                    return
                except:
                    print_error("There was an error!")
                    os.chdir(prev_cwd)
                    return
                finally:
                    os.chdir(prev_cwd)
                return
                
                
            # If theres no password just zip it up
            with ZipFile(export_path, 'w') as export_zip:
                export_zip.write(__session__.file.path, arcname=os.path.basename(__session__.file.path))
                print_info("File Exported to {0}".format(export_path))
            return


        # Start here
        if not __session__.is_set():
            print_error("No session opened")
            return
        
        # Get Options and Args
        try:
            opts, argv = getopt.getopt(self.args, 'hzp:', ['help', 'zip', 'pass='])
        except getopt.GetoptError as e:
            print(e)
            return
        
        # We need at least one arg
        if len(argv) == 0:
            help()
            return

        # File error handling, overwrite, dest is dir etc
        if os.path.isdir(argv[0]):
            print_error("{0} is a Directory".format(argv[0]))
            return
        if os.path.isfile(argv[0]):
            print_error("{0} alreadyExists, can't Overwrite".format(argv[0]))
            return
        
        # Get options and process accordingly
        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-p', '--pass'):
                compress(value, argv[0])
                return
            elif opt in ('-z', '--zip'):
                compress(None, argv[0])
                return

        # if no options straight copy
        shutil.copyfile(__session__.file.path, argv[0])
        print_info("File Exported to {0}".format(argv[0]))




        
