'''
Created on 2015-10-10

@author: S2R2

Based on https://github.com/S2R2/WinntiAnalysisTools/blob/master/dumpWinntiConf.py

'''

import binascii
from struct import unpack_from

def xorStrHex(str1,key):
    decoded = ''
    for c in str1:
        decoded = decoded + chr(ord(c)^key)
        key = key + 1
        if(key > 0xff):
            key = 0x00
    return decoded

def extractConfig(confStr):
    extract =  unpack_from("100s32s32s24s4s4s4si4s32s32s32s21h4s",confStr)
    conf = {
          'C2': extract[0],
          'CampaignID1': extract[1],
          'CampaignID2': extract[2],
          'CampaignIDNumber': extract[3],
          'CommMode': extract[7],
          'ProxyType': binascii.hexlify(extract[8]),
          'ProxyServer': extract[9],
          'ProxyUser': extract[10],
          'ProxyPassword': extract[11],
          'ReconnectTime': unpack_from('i',extract[33])[0]
          }
    
    if conf['CommMode'] == 1:
        conf['CommMode'] = '1 (Custom TCP)'
    elif conf['CommMode'] == 2:
        conf['CommMode'] = '2 (HTTPS)'
    elif conf['CommMode'] == 3:
        conf['CommMode'] = '3 (HTTP)'
    else:
        conf['CommMode'] = str(conf['dwCommMode']) + '(Unknown)'
        
    return conf

def config(data):
    
    configStart = len(data) - (unpack_from("i",data[len(data)-4:])[0] +4)
    decoded=xorStrHex(data[configStart:configStart+350], 0x99)
    config = extractConfig(decoded)
    
    return config
