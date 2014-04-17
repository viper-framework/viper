# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/BlackNix.py

import os
import sys
from zipfile import ZipFile
from cStringIO import StringIO

from viper.common.out import *

def configExtract(rawData):
	try:
		pe = pefile.PE(data=rawData)

		try:
		  rt_string_idx = [
		  entry.id for entry in 
		  pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
		except ValueError, e:
			sys.exit()
		except AttributeError, e:
			sys.exit()

		rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

		for entry in rt_string_directory.directory.entries:
			if str(entry.name) == "SETTINGS":
				data_rva = entry.directory.entries[0].data.struct.OffsetToData
				size = entry.directory.entries[0].data.struct.Size
				data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
				config = data.split('}')
				return config
	except:
		return None		

def decode(line):
	result = ""
	for i in range(0,len(line)):
		a = ord(line[i])
		result += chr(a-1)
	return result

def config(data):
	try:
		conf = {}
		config = configExtract(data)
		if config != None:
			for i in range(0,len(config)):
				print i, decode(config[i])[::-1]
			conf["Mutex"] = decode(config[1])[::-1]
			conf["Anti Sandboxie"] = decode(config[2])[::-1]
			conf["Max Folder Size"] = decode(config[3])[::-1]
			conf["Delay Time"] = decode(config[4])[::-1]
			conf["Password"] = decode(config[5])[::-1]
			conf["Kernel Mode Unhooking"] = decode(config[6])[::-1]
			conf["User More Unhooking"] = decode(config[7])[::-1]
			conf["Melt Server"] = decode(config[8])[::-1]
			conf["Offline Screen Capture"] = decode(config[9])[::-1]
			conf["Offline Keylogger"] = decode(config[10])[::-1]
			conf["Copy To ADS"] = decode(config[11])[::-1]
			conf["Domain"] = decode(config[12])[::-1]
			conf["Persistence Thread"] = decode(config[13])[::-1]
			conf["Active X Key"] = decode(config[14])[::-1]
			conf["Registry Key"] = decode(config[15])[::-1]
			conf["Active X Run"] = decode(config[16])[::-1]
			conf["Registry Run"] = decode(config[17])[::-1]
			conf["Safe Mode Startup"] = decode(config[18])[::-1]
			conf["Inject winlogon.exe"] = decode(config[19])[::-1]
			conf["Install Name"] = decode(config[20])[::-1]
			conf["Install Path"] = decode(config[21])[::-1]
			conf["Campaign Name"] = decode(config[22])[::-1]
			conf["Campaign Group"] = decode(config[23])[::-1]
			return conf
		else:
			return None
	except:
		return None

