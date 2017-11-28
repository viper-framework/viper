# -*- coding: utf-8 -*-
# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/DarkComet.py

import string
import pefile
from binascii import unhexlify

BASE_CONFIG = {
    'FWB': '',
    'GENCODE': '',
    'MUTEX': '',
    'NETDATA': '',
    'OFFLINEK': '',
    'SID': '',
    'FTPUPLOADK': '',
    'FTPHOST': '',
    'FTPUSER': '',
    'FTPPASS': '',
    'FTPPORT': '',
    'FTPSIZE': '',
    'FTPROOT': '',
    'PWD': ''
}


def rc4crypt(data, key):
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)


def v51_data(data, key):
    config = BASE_CONFIG
    dec = rc4crypt(unhexlify(data), key)
    dec_list = dec.split('\n')
    for entries in dec_list[1:-1]:
        key, value = entries.split('=')
        key = key.strip()
        value = value.rstrip()[1:-1]
        clean_value = [x for x in value if x in string.printable]
        config[key] = clean_value

    return config


def version_check(raw_data):
    if '#KCMDDC2#' in raw_data:
        return '#KCMDDC2#-890'
    elif '#KCMDDC4#' in raw_data:
        return '#KCMDDC4#-890'
    elif '#KCMDDC42#' in raw_data:
        return '#KCMDDC42#-890'
    elif '#KCMDDC42F#' in raw_data:
        return '#KCMDDC42F#-890'
    elif '#KCMDDC5#' in raw_data:
        return '#KCMDDC5#-890'
    elif '#KCMDDC51#' in raw_data:
        return '#KCMDDC51#-890'
    else:
        return None


def extract_config(raw_data, key):
    config = BASE_CONFIG

    pe = pefile.PE(data=raw_data)

    rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

    for entry in rt_string_directory.directory.entries:
        if str(entry.name) == 'DCDATA':
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
            config = v51_data(data, key)
        elif str(entry.name) in list(config.keys()):
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
            dec = rc4crypt(unhexlify(data), key)
            config[str(entry.name)] = [x for x in dec if x in string.printable]

    return config


def config(data):
    versionKey = version_check(data)
    if versionKey:
        return extract_config(data, versionKey)
    else:
        return None
