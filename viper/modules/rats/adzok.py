# -*- coding: utf-8 -*-
#  Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/Adzok.py

import re
import string
from zipfile import ZipFile
from io import StringIO


# Helper Functions Go Here
def string_print(line):
    return [x for x in line if x in string.printable]


def parse_config(raw_config):
    config_dict = {}
    for line in raw_config.split('\n'):
        if line.startswith('<comment'):
            config_dict['Version'] = re.findall('>(.*?)</comment>', line)[0]
        if line.startswith('<entry key'):
            try:
                config_dict[re.findall('key="(.*?)"', line)[0]] = re.findall('>(.*?)</entry', line)[0]
            except Exception:
                config_dict[re.findall('key="(.*?)"', line)[0]] = 'Not Set'
            finally:
                pass

    # Tidy the config
    clean_config = {}
    for k, v in config_dict.items():
        if k == 'dir':
            clean_config['Install Path'] = v
        if k == 'reg':
            clean_config['Registrey Key'] = v
        if k == 'pass':
            clean_config['Password'] = v
        if k == 'hidden':
            clean_config['Hidden'] = v
        if k == 'puerto':
            clean_config['Port'] = v
        if k == 'ip':
            clean_config['Domain'] = v
        if k == 'inicio':
            clean_config['Install'] = v

    return clean_config


def config(data):
    raw_config = False
    jar_file = StringIO(data)
    with ZipFile(jar_file, 'r') as jar:
        for name in jar.namelist():
            if name == 'config.xml':
                raw_config = jar.read(name)
    if raw_config:
        return parse_config(raw_config)
