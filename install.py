#!/usr/bin/python
# 
#  Ubuntu 14.04.02
#

import os

os.system('sudo apt-get -y install gcc git python-dev python-pip python-socksipy swig')
os.system('wget http://sourceforge.net/projects/ssdeep/files/ssdeep-2.12/ssdeep-2.12.tar.gz')
os.system('tar -zxvf ssdeep-2.12.tar.gz')
os.system('cd ssdeep-2.12 && ./configure && make && sudo make install')
os.system('sudo pip install SQLAlchemy PrettyTable python-magic pydeep')
os.system('git clone https://github.com/botherder/viper.git')
os.system('cd viper && sudo pip install -r requirements.txt')
