# -*- coding: utf-8 -*-
# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/Arcom.py

import base64
from Crypto.Cipher import Blowfish


def decrypt_blowfish(raw_data):
    key = 'CVu3388fnek3W(3ij3fkp0930di'
    cipher = Blowfish.new(key)
    return cipher.decrypt(raw_data)


def config(data):
    try:
        config = {}
        config_raw = data.split('\x18\x12\x00\x00')[1].replace('\xA3\x24\x25\x21\x64\x01\x00\x00', '')
        config_decoded = base64.b64decode(config_raw)
        config_decrypted = decrypt_blowfish(config_decoded)
        parts = config_decrypted.split('|')

        if len(parts) > 3:
            config['Domain'] = parts[0]
            config['Port'] = parts[1]
            config['Install Path'] = parts[2]
            config['Install Name'] = parts[3]
            config['Startup Key'] = parts[4]
            config['Campaign ID'] = parts[5]
            config['Mutex Main'] = parts[6]
            config['Mutex Per'] = parts[7]
            config['YPER'] = parts[8]
            config['YGRB'] = parts[9]
            config['Mutex Grabber'] = parts[10]
            config['Screen Rec Link'] = parts[11]
            config['Mutex 4'] = parts[12]
            config['YVID'] = parts[13]
            config['YIM'] = parts[14]
            config['NO'] = parts[15]
            config['Smart Broadcast'] = parts[16]
            config['YES'] = parts[17]
            config['Plugins'] = parts[18]
            config['Flag1'] = parts[19]
            config['Flag2'] = parts[20]
            config['Flag3'] = parts[21]
            config['Flag4'] = parts[22]
            config['WebPanel'] = parts[23]
            config['Remote Delay'] = parts[24]
        return config
    except Exception:
        return None
