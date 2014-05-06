# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/BlueBanana.py

import os
import sys
import string
from zipfile import ZipFile
from cStringIO import StringIO
from Crypto.Cipher import AES


from viper.common.out import *

def DecryptAES(enckey, data):
	cipher = AES.new(enckey) # set the cipher
	return cipher.decrypt(data) # decrpyt the data

def decryptConf(conFile):
	key1 = "15af8sd4s1c5s511"
	key2 = "4e3f5a4c592b243f"
	first = DecryptAES(key1, conFile.decode('hex'))
	second = DecryptAES(key2, first[:-16].decode('hex'))
	return second
	
def configParse(confRaw):
	conf = {}
	clean = filter(lambda x: x in string.printable, confRaw)
	list = clean.split("<separator>")
	conf["Domain"] = list[0]
	conf["Password"] = list[1]
	conf["Port1"] = list[2]
	conf["Port2"] = list[3]
	if len(list) > 4:
		conf["InstallName"] = list[4]
		conf["JarName"] = list[5]
	return conf

def config(data):
	newZip = StringIO(data)
	with ZipFile(newZip) as zip:
		for name in zip.namelist(): # get all the file names
			if name == "config.txt": # this file contains the encrypted config
				conFile = zip.read(name)
	if conFile: # 
		confRaw = decryptConf(conFile)
		conf = configParse(confRaw)
	return conf
