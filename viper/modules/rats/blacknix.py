# -*- coding: utf-8 -*-
# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/BlackNix.py

import pefile


def extract_config(raw_data):
    try:
        pe = pefile.PE(data=raw_data)

        try:
            rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
        except Exception:
            return None

        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == 'SETTINGS':
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                config = data.split('}')
                return config
    except Exception:
        return None


def decode(line):
    result = ''
    for i in range(0, len(line)):
        a = ord(line[i])
        result += chr(a - 1)
    return result


def config(data):
    try:
        config = {}
        config_raw = extract_config(data)
        if config_raw:
            config['Mutex'] = decode(config_raw[1])[::-1]
            config['Anti Sandboxie'] = decode(config_raw[2])[::-1]
            config['Max Folder Size'] = decode(config_raw[3])[::-1]
            config['Delay Time'] = decode(config_raw[4])[::-1]
            config['Password'] = decode(config_raw[5])[::-1]
            config['Kernel Mode Unhooking'] = decode(config_raw[6])[::-1]
            config['User More Unhooking'] = decode(config_raw[7])[::-1]
            config['Melt Server'] = decode(config_raw[8])[::-1]
            config['Offline Screen Capture'] = decode(config_raw[9])[::-1]
            config['Offline Keylogger'] = decode(config_raw[10])[::-1]
            config['Copy To ADS'] = decode(config_raw[11])[::-1]
            config['Domain'] = decode(config_raw[12])[::-1]
            config['Persistence Thread'] = decode(config_raw[13])[::-1]
            config['Active X Key'] = decode(config_raw[14])[::-1]
            config['Registry Key'] = decode(config_raw[15])[::-1]
            config['Active X Run'] = decode(config_raw[16])[::-1]
            config['Registry Run'] = decode(config_raw[17])[::-1]
            config['Safe Mode Startup'] = decode(config_raw[18])[::-1]
            config['Inject winlogon.exe'] = decode(config_raw[19])[::-1]
            config['Install Name'] = decode(config_raw[20])[::-1]
            config['Install Path'] = decode(config_raw[21])[::-1]
            config['Campaign Name'] = decode(config_raw[22])[::-1]
            config['Campaign Group'] = decode(config_raw[23])[::-1]
            return config
        else:
            return None
    except Exception:
        return None
