# -*- coding: utf-8 -*-
# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/Bozok.py

import pefile


def extract_config(raw_data):
    pe = pefile.PE(data=raw_data)

    try:
        rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
    except Exception:
        return None

    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

    for entry in rt_string_directory.directory.entries:
        if str(entry.name) == 'CFG':
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
            return data


def config(data):
    try:
        config = {}
        config_raw = extract_config(data).replace('\x00', '')

        if not config_raw:
            return None

        config_fields = config_raw.split('|')

        if config_fields:
            config['ServerID'] = config_fields[0]
            config['Mutex'] = config_fields[1]
            config['InstallName'] = config_fields[2]
            config['StartupName'] = config_fields[3]
            config['Extension'] = config_fields[4]
            config['Password'] = config_fields[5]
            config['Install Flag'] = config_fields[6]
            config['Startup Flag'] = config_fields[7]
            config['Visible Flag'] = config_fields[8]
            config['Unknown Flag1'] = config_fields[9]
            config['Unknown Flag2'] = config_fields[10]
            config['Port'] = config_fields[11]
            config['Domain'] = config_fields[12]
            config['Unknown Flag3'] = config_fields[13]
        return config
    except Exception:
        return None
