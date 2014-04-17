# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/Arcom.py

import base64
import string
from Crypto.Cipher import Blowfish

from viper.common.out import *

def decryptBlowfish(rawData):
	key = "CVu3388fnek3W(3ij3fkp0930di"
	cipher = Blowfish.new(key)
	return cipher.decrypt(rawData)

def config(data):
	try:
		conf = {}
		config = data.split("\x18\x12\x00\x00")[1].replace('\xA3\x24\x25\x21\x64\x01\x00\x00','')
		configdecode = base64.b64decode(config)
		configDecrypt = decryptBlowfish(configdecode)
		parts = configDecrypt.split('|')
		if len(parts) > 3:
			conf["Domain"] = parts[0]
			conf["Port"] = parts[1]
			conf["Install Path"] = parts[2]
			conf["Install Name"] = parts[3]
			conf["Startup Key"] = parts[4]
			conf["Campaign ID"] = parts[5]
			conf["Mutex Main"] = parts[6]
			conf["Mutex Per"] = parts[7]
			conf["YPER"] = parts[8]
			conf["YGRB"] = parts[9]
			conf["Mutex Grabber"] = parts[10]
			conf["Screen Rec Link"] = parts[11]
			conf["Mutex 4"] = parts[12]
			conf["YVID"] = parts[13]
			conf["YIM"] = parts[14]
			conf["NO"] = parts[15]
			conf["Smart Broadcast"] = parts[16]
			conf["YES"] = parts[17]
			conf["Plugins"] = parts[18]
			conf["Flag1"] = parts[19]
			conf["Flag2"] = parts[20]
			conf["Flag3"] = parts[21]
			conf["Flag4"] = parts[22]
			conf["WebPanel"] = parts[23]
			conf["Remote Delay"] = parts[24]
		return conf
	except:
		return None




