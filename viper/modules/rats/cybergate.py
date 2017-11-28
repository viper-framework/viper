# -*- coding: utf-8 -*-
# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/DarkComet.py

import pefile


def xor(data):
    key = 0xBC
    encoded = bytearray(data)
    for i in range(len(encoded)):
        encoded[i] ^= key
    return str(encoded).decode('ascii', 'replace')


def extract_config(raw_data):
    try:
        pe = pefile.PE(data=raw_data)

        try:
            rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
        except Exception:
            return None

        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == 'XX-XX-XX-XX' or str(entry.name) == 'CG-CG-CG-CG':
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                config = data.split('####@####')
                return config
    except Exception:
        return None


def config(data):
    conf = {}
    raw_conf = extract_config(data)
    if raw_conf:
        if len(raw_conf) > 20:
            domains = ''
            ports = ''
            # Config sections 0 - 19 contain a list of Domains and Ports
            for i in range(0, 19):
                if len(raw_conf[i]) > 1:
                    domains += xor(raw_conf[i]).split(':')[0]
                    domains += ','
                    ports += xor(raw_conf[i]).split(':')[1]
                    ports += ','

            conf['Domain'] = domains
            conf['Port'] = ports
            conf['CampaignID'] = xor(raw_conf[20])
            conf['Password'] = xor(raw_conf[21])
            conf['InstallFlag'] = xor(raw_conf[22])
            conf['InstallDir'] = xor(raw_conf[25])
            conf['InstallFileName'] = xor(raw_conf[26])
            conf['ActiveXStartup'] = xor(raw_conf[27])
            conf['REGKeyHKLM'] = xor(raw_conf[28])
            conf['REGKeyHKCU'] = xor(raw_conf[29])
            conf['EnableMessageBox'] = xor(raw_conf[30])
            conf['MessageBoxIcon'] = xor(raw_conf[31])
            conf['MessageBoxButton'] = xor(raw_conf[32])
            conf['InstallMessageTitle'] = xor(raw_conf[33])
            conf['InstallMessageBox'] = xor(raw_conf[34])
            conf['ActivateKeylogger'] = xor(raw_conf[35])
            conf['KeyloggerBackspace'] = xor(raw_conf[36])
            conf['KeyloggerEnableFTP'] = xor(raw_conf[37])
            conf['FTPAddress'] = xor(raw_conf[38])
            conf['FTPDirectory'] = xor(raw_conf[39])
            conf['FTPUserName'] = xor(raw_conf[41])
            conf['FTPPassword'] = xor(raw_conf[42])
            conf['FTPPort'] = xor(raw_conf[43])
            conf['FTPInterval'] = xor(raw_conf[44])
            conf['Persistance'] = xor(raw_conf[59])
            conf['HideFile'] = xor(raw_conf[60])
            conf['ChangeCreationDate'] = xor(raw_conf[61])
            conf['Mutex'] = xor(raw_conf[62])
            conf['MeltFile'] = xor(raw_conf[63])
            conf['CyberGateVersion'] = xor(raw_conf[67])
            conf['StartupPolicies'] = xor(raw_conf[69])
            conf['USBSpread'] = xor(raw_conf[70])
            conf['P2PSpread'] = xor(raw_conf[71])
            conf['GoogleChromePasswords'] = xor(raw_conf[73])

        if xor(raw_conf[57]) == 0 or xor(raw_conf[57]) is None:
            conf['ProcessInjection'] = 'Disabled'
        elif xor(raw_conf[57]) == 1:
            conf['ProcessInjection'] = 'Default Browser'
        elif xor(raw_conf[57]) == 2:
            conf['ProcessInjection'] = xor(raw_conf[58])

        return conf
