# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/Adzok.py

import os
import re
import sys
import string
from zipfile import ZipFile

#Helper Functions Go Here
def string_print(line):
    return filter(lambda x: x in string.printable, line)
    
def parse_config(raw_config):
    config_dict = {}
    for line in raw_config.split('\n'):
        if line.startswith('<comment'):
            config_dict['Version'] = re.findall('>(.*?)</comment>', line)[0]
        if line.startswith('<entry key'):
            config_dict[re.findall('key="(.*?)"', line)[0]] = re.findall('>(.*?)</entry', line)[0]
    return config_dict


def config(data):
    raw_config = False
    with ZipFile(file_name, 'r') as zip:
        for name in zip.namelist():
            if name == 'config.xml':
                raw_config = zip.read(name)
    if raw_config:
        return parse_config(raw_config)

