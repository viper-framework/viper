#!/usr/bin/python
import getopt
import os
from collections import defaultdict

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.storage import get_sample_path
from viper.core.database import Database

try:
    from pehash.pehasher import calculate_pehash
    HAVE_PEHASH = True
except ImportError:
    HAVE_PEHASH = False

class pehash(Module):
    cmd = 'pehash'
    description = 'Calculate PEhash of all files or the open file'
    authors = ['Statixs']

    def run(self):
        def usage():
            print("usage: pehash [-hfa]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--file (-f)\tPrints the PEhash of the open file")
            print("\t--all (-a)\tPrints the PEhash of all files in the project")
            print("")

        def calc_hash(data):
            if not HAVE_PEHASH:
                print_error("PEhash not installed, or PEhash is not placed in a function. Please copy PEhash to the modules directory of Viper.")
            db = Database()

            # Get all the files and calculate 
            if data == True:
                samples = db.find(key='all')

                # Calculate and print PEhash for all samples in a table
                header = ['Name', 'PEhash']
                rows = []
                for sample in samples:
                    sample_path = get_sample_path(sample.sha256)
                    result = calculate_pehash(sample_path)
                    rows.append((sample.name, result))
                print(table(header=header, rows=rows))

                # Compare samples. sn=sample name, ph=pehash
                d = {}
                for sn,ph in rows:
                    d.setdefault(ph,[]).append(sn)
                
                for i in d.items():
                    if len(i[1]) > 1:
                        print("PEhash "+i[0]+"was calculated on files:")
                        for f in i[1]:
                            print("\t"+f)

            # Calculate the PEhash of single file based on SHA256 hash
            else:
                sample = db.find(key='sha256', value=data)
                
                # Check if the sample hash is equal to the hash of the current open session file then calculate the PEhash
                if sample[0].sha256 == data:
                    sample_path = get_sample_path(sample[0].sha256)
                    result = calculate_pehash(sample_path)
                    print('The PEhash is: ' + result)

        try:
            opts, argv = getopt.getopt(self.args[0:], 'hfa', ['help', 'file', 'all'])
        except getopt.GetoptError as e:
            print(e)
            return
        
        # The argument handler
        argument = False
        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return

            elif opt in ('-f', '--file'):
                if not __sessions__.is_set():
                    print_error('No session opened')
                    return
                argument = True 
                calc_hash(__sessions__.current.file.sha256)

            elif opt in ('-a', '--all'):
                argument = True 
                calc_hash(True)

        if not argument:
            usage()
