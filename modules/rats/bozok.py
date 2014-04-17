# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/Bozok.py

import os
import sys
import pefile

from viper.common.out import *

def configExtract(rawData):

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
			if str(entry.name) == "CFG":
				data_rva = entry.directory.entries[0].data.struct.OffsetToData
				size = entry.directory.entries[0].data.struct.Size
				data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
				return data
				
def config(data):
	try:
		conf = {}
		rawConfig = configExtract(data).replace('\x00', '')
		config = rawConfig.split("|")
		print config
		if config != None:
			conf["ServerID"] = config[0]
			conf["Mutex"] = config[1]
			conf["InstallName"] = config[2]
			conf["StartupName"] = config[3]
			conf["Extension"] = config[4]
			conf["Password"] = config[5]
			conf["Install Flag"] = config[6]
			conf["Startup Flag"] = config[7]
			conf["Visible Flag"] = config[8]
			conf["Unknown Flag1"] = config[9]
			conf["Unknown Flag2"] = config[10]
			conf["Port"] = config[11]
			conf["Domain"] = config[12]
			conf["Unknown Flag3"] = config[13]
		return conf
	except:
		return None