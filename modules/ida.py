# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt
import magic
import pefile

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

IMAGE_DLL_CHARACTERISTICS_DRIVER  = 0x400
ext = ".bin"

class Ida(Module):
    cmd = 'ida'
    description = 'Start IDA Pro'
    authors = ['Sascha Rommelfangen']

    def OpenIDA(self, filename, ext, arch):
        directory = filename + ".dir"
        if not os.path.exists(directory):
            os.makedirs(directory)
        destination = directory + "/executable" + ext
        print destination
        if not os.path.lexists(destination):
            os.link(filename, destination)
        if arch == 0:
            command = "open -a idaq " + destination
            os.system(command)
        if arch == 1:
            command = "open -a idaq64 " + destination
            os.system(command)

    def run(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        try:
            filename = __sessions__.current.file.path
            type = magic.from_file(filename)
            if "PE32 " in type:
                if "DLL" in type:
                    print "32 bit DLL"
                    if "native" in type:
                        print "perhaps a driver (.sys)" 
                    ext = ".dll"
                else:
                     print "32 bit EXE"
                     ext = ".exe"
                try:
                    self.OpenIDA(filename, ext, 0)
                except:
                    print_error("Unable to start IDA Pro")
            elif "PE32+" in type:
                if "DLL" in type:
                    print "64 bit DLL"
                    if "native" in type:
                        print "perhaps a driver (.sys)"
                    ext = ".dll"
                else:
                    print "64 bit EXE"
                    ext = ".exe"
                try:
                    self.OpenIDA(filename, ext, 0)
                except:
                    print_error("Unable to start IDA Pro")
            else:
                print "not recognized"  
                print type
        except OSError:
            print_error("IDA is not installed")
            return

