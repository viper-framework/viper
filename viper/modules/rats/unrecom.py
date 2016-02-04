# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/unrecom.py

import string
from zipfile import ZipFile
from cStringIO import StringIO
from Crypto.Cipher import ARC4
import xml.etree.ElementTree as ET

from viper.common.out import print_info

def extract_embedded(zip_data):
    raw_embedded = None
    archive = StringIO(zip_data)
    with ZipFile(archive) as zip:
        for name in zip.namelist(): # get all the file names
            if name == "load/ID": # contains first part of key
                partial_key = zip.read(name)
                enckey = partial_key + 'DESW7OWKEJRU4P2K' # complete key
                print_info("Encryption Key {0}".format(zip.read(name)))
            if name == "load/MANIFEST.MF": # this is the embedded jar                
                raw_embedded = zip.read(name)
    if raw_embedded != None:
        # Decrypt The raw file
        dec_embedded = decrypt_arc4(enckey, raw_embedded)
        return dec_embedded
    else:
        return None

def parse_embedded(data):
    newzipdata = data
    newZip = StringIO(newzipdata) # Write new zip file to memory instead of to disk
    with ZipFile(newZip) as zip:
        for name in zip.namelist():
            if name == "config.xml": # this is the config in clear
                config = zip.read(name)
    return config
        
def decrypt_arc4(enckey, data):
        cipher = ARC4.new(enckey) # set the ciper
        return cipher.decrypt(data) # decrpyt the data

def parse_config(config):
    #try:
        xml = filter(lambda x: x in string.printable, config)
        root = ET.fromstring(xml)
        raw_config = {}
        for child in root:
            if child.text.startswith("Unrecom"):
                raw_config["Version"] = child.text
            else:
                raw_config[child.attrib["key"]] = child.text
        new_config = {}
        new_config['Version'] = raw_config['Version']
        new_config['Delay'] = raw_config['delay']
        new_config['Domain'] = raw_config['dns']
        new_config['Extension'] = raw_config['extensionname']
        new_config['Install'] = raw_config['install']
        new_config['Port1'] = raw_config['p1']
        new_config['Port2'] = raw_config['p2']
        new_config['Password'] = raw_config['password']
        new_config['PluginFolder'] = raw_config['pluginfoldername']
        new_config['Prefix'] = raw_config['prefix']    
        return new_config
    #except:
        #return None


def config(data):
    embedded = extract_embedded(data)
    if embedded is not None:
        config = parse_embedded(embedded)
    else:
        return None
    if config is not None:
        return parse_config(config)
    else:
        return None
