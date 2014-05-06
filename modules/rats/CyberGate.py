# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/DarkComet.py

import sys
import string
from struct import unpack
import pefile
from binascii import *

def xorDecode(data):
    key = 0xBC
    encoded = bytearray(data)
    for i in range(len(encoded)):
        encoded[i] ^= key
    return str(encoded).decode("ascii", "replace")

def configExtract(rawData):
    try:
        pe = pefile.PE(data=rawData)

        try:
          rt_string_idx = [
          entry.id for entry in 
          pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
        except ValueError, e:
            return None
        except AttributeError, e:
            return None

        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "XX-XX-XX-XX" or str(entry.name) == "CG-CG-CG-CG":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                config = data.split('####@####')
                return config
    except:
        return None
    
def config(data):
    confDict  = {}
    rawConf = configExtract(data)
    if rawConf != None:
        if len(rawConf) > 20:
            domains = ""
            ports = ""
            #Config sections 0 - 19 contain a list of Domains and Ports
            for i in range(0,19):
                if len(rawConf[i]) > 1:
                    domains += xorDecode(rawConf[i]).split(':')[0]
                    domains += ","
                    ports += xorDecode(rawConf[i]).split(':')[1]
                    ports += ","
                
            confDict ["Domain"] = domains
            confDict ["Port"] = ports
            confDict ["CampaignID"] = xorDecode(rawConf[20])
            confDict ["Password"] = xorDecode(rawConf[21])
            confDict ["InstallFlag"] = xorDecode(rawConf[22])
            confDict ["InstallDir"] = xorDecode(rawConf[25])
            confDict ["InstallFileName"] = xorDecode(rawConf[26])
            confDict ["ActiveXStartup"] = xorDecode(rawConf[27])
            confDict ["REGKeyHKLM"] = xorDecode(rawConf[28])
            confDict ["REGKeyHKCU"] = xorDecode(rawConf[29])
            confDict ["EnableMessageBox"] = xorDecode(rawConf[30])
            confDict ["MessageBoxIcon"] = xorDecode(rawConf[31])
            confDict ["MessageBoxButton"] = xorDecode(rawConf[32])
            confDict ["InstallMessageTitle"] = xorDecode(rawConf[33])
            confDict ["InstallMessageBox"] = xorDecode(rawConf[34])
            confDict ["ActivateKeylogger"] = xorDecode(rawConf[35])
            confDict ["KeyloggerBackspace"] = xorDecode(rawConf[36])
            confDict ["KeyloggerEnableFTP"] = xorDecode(rawConf[37])
            confDict ["FTPAddress"] = xorDecode(rawConf[38])
            confDict ["FTPDirectory"] = xorDecode(rawConf[39])
            confDict ["FTPUserName"] = xorDecode(rawConf[41])
            confDict ["FTPPassword"] = xorDecode(rawConf[42])
            confDict ["FTPPort"] = xorDecode(rawConf[43])
            confDict ["FTPInterval"] = xorDecode(rawConf[44])
            confDict ["Persistance"] = xorDecode(rawConf[59])
            confDict ["HideFile"] = xorDecode(rawConf[60])
            confDict ["ChangeCreationDate"] = xorDecode(rawConf[61])
            confDict ["Mutex"] = xorDecode(rawConf[62])        
            confDict ["MeltFile"] = xorDecode(rawConf[63])
            confDict ["CyberGateVersion"] = xorDecode(rawConf[67])        
            confDict ["StartupPolicies"] = xorDecode(rawConf[69])
            confDict ["USBSpread"] = xorDecode(rawConf[70])
            confDict ["P2PSpread"] = xorDecode(rawConf[71])
            confDict ["GoogleChromePasswords"] = xorDecode(rawConf[73])
        if xorDecode(rawConf[57]) == 0 or xorDecode(rawConf[57]) == None:
            confDict ["ProcessInjection"] = "Disabled"
        elif xorDecode(rawConf[57]) == 1:
            confDict ["ProcessInjection"] = "Default Browser"
        elif xorDecode(rawConf[57]) == 2:
            confDict ["ProcessInjection"] = xorDecode(rawConf[58])
        return confDict
