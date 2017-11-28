# -*- coding: utf-8 -*-
# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/ClientMesh.py

# Standard Imports Go Here
from base64 import b64decode
from zipfile import ZipFile
from io import StringIO
from Crypto.Cipher import AES, DES3


# Helper Functions Go Here

# This extracts the Encryption Key and Config File from the Jar and or Dropper
def get_parts(data):
    new_zip = StringIO(data)
    enckey = None
    dropper = None
    conf = None
    try:
        with ZipFile(new_zip, 'r') as zip:
            for name in zip.namelist():  # get all the file names
                if name == "key.dat":  # this file contains the encrytpion key
                    enckey = zip.read(name)
                if name == "enc.dat":  # if this file exists, jrat has an installer / dropper
                    dropper = zip.read(name)
                if name == "config.dat":  # this is the encrypted config file
                    conf = zip.read(name)
    except Exception:
        return None, None
    if enckey and conf:
        return enckey, conf
    elif enckey and dropper:
        newkey, conf = get_dropper(enckey, dropper)
        return newkey, conf
    else:
        return None, None


# This extracts the Encryption Key and New conf from a 'Dropper' jar
def get_dropper(enckey, dropper):
    try:
        split = enckey.split('\x2c')
        key = split[0][:16]
        # TODO: This loop makes no sense. "drop" isn't used anywhere.
        """for x in split: # grab each line of the config and decode it.
            try:
                drop = b64decode(x).decode('hex')
            except:
                drop = b64decode(x[16:]).decode('hex')"""
        new_zipdata = decrypt_aes(key, dropper)
        new_key, conf = get_parts(new_zipdata)
        return new_key, conf
    except Exception:
        return None, None


# Returns only printable chars
def string_print(line):
    return ''.join((char for char in line if 32 < ord(char) < 127))


# Messy Messy Messy
def messy_split(long_line):
    # this is a messy way to split the data but it works for now.
    '''
    Split on = gives me the right sections but deletes the b64 padding
    use modulo math to restore padding.
    return new list.
    '''
    new_list = []
    old_list = long_line.split('=')
    for line in old_list:
        if len(line) != 0:
            line += "=" * ((4 - len(line) % 4) % 4)
            new_list.append(line)
    return new_list


# AES Decrypt
def decrypt_aes(enckey, data):
    cipher = AES.new(enckey)  # set the cipher
    return cipher.decrypt(data)  # decrpyt the data


# DES Decrypt
def decrypt_des(enckey, data):
    cipher = DES3.new(enckey)  # set the ciper
    return cipher.decrypt(data)  # decrpyt the data


# Process Versions 3.2.2 > 4.2.
def old_aes(conf, enckey):
    decoded_config = decrypt_aes(enckey, conf)
    clean_config = string_print(decoded_config)
    raw_config = clean_config.split('SPLIT')
    return raw_config


# Process versions 4.2. >
def new_aes(conf, enckey):
    sections = messy_split(conf)
    decoded_config = ''
    for x in sections:
        decoded_config += decrypt_aes(enckey, b64decode(x))
    raw_config = string_print(decoded_config).split('SPLIT')
    return raw_config


# process versions < 3.2.2
def old_des(conf, enckey):
    decoded_config = decrypt_des(enckey, conf)
    clean_config = string_print(decoded_config)
    raw_config = clean_config.split('SPLIT')
    return raw_config


def parse_config(raw_config, enckey):
    config_dict = {}
    for kv in raw_config:
        if kv == '':
            continue
        kv = string_print(kv)
        key, value = kv.split('=')
        if key == 'ip':
            config_dict['Domain'] = value
        if key == 'addresses':
            dom_list = value.split(',')
            dom_count = 0
            for dom in dom_list:
                if dom == '':
                    continue
                config_dict['Domain {0}'.format(dom_count)] = value.split(':')[0]
                config_dict['Port {0}'.format(dom_count)] = value.split(':')[1]
                dom_count += 1
        if key == 'port':
            config_dict['Port'] = value
        if key == 'os':
            config_dict['OS'] = value
        if key == 'mport':
            config_dict['MPort'] = value
        if key == 'perms':
            config_dict['Perms'] = value
        if key == 'error':
            config_dict['Error'] = value
        if key == 'reconsec':
            config_dict['RetryInterval'] = value
        if key == 'ti':
            config_dict['TI'] = value
        if key == 'pass':
            config_dict['Password'] = value
        if key == 'id':
            config_dict['CampaignID'] = value
        if key == 'mutex':
            config_dict['Mutex'] = value
        if key == 'toms':
            config_dict['TimeOut'] = value
        if key == 'per':
            config_dict['Persistance'] = value
        if key == 'name':
            config_dict['InstallName'] = value
        if key == 'tiemout':
            config_dict['TimeOutFlag'] = value
        if key == 'debugmsg':
            config_dict['DebugMsg'] = value
    config_dict["EncryptionKey"] = enckey.encode('hex')
    return config_dict


def config(data):
    enckey, conf = get_parts(data)
    if enckey is None:
        return
    if len(enckey) == 16:
        # Newer versions use a base64 encoded config.dat
        if '==' in conf:  # this is not a great test but should work 99% of the time
            b64_check = True
        else:
            b64_check = False
        if b64_check:
            raw_config = new_aes(conf, enckey)
        else:
            raw_config = old_aes(conf, enckey)
    if len(enckey) in [24, 32]:
        raw_config = old_des(conf, enckey)
    config_dict = parse_config(raw_config, enckey)
    return config_dict
