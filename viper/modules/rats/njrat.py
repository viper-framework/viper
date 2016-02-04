# Originally written by Kevin Breen (@KevTheHermit):
# https://github.com/kevthehermit/RATDecoders/blob/master/njRat.py

import base64
import pype32


#Helper Functions Go Here

# Get a list of strings from a section
def get_strings(pe, dir_type):
    counter = 0
    string_list = []
    m = pe.ntHeaders.optionalHeader.dataDirectory[14].info
    for s in m.netMetaDataStreams[dir_type].info:
        for offset, value in s.iteritems():
            string_list.append(value)
        counter += 1
    return string_list
            
#Turn the strings in to a python config_dict
def parse_config(string_list):
    config_dict = {}
    if string_list[5] == '0.3.5':
        config_dict["Campaign ID"] = base64.b64decode(string_list[4])
        config_dict["version"] = string_list[5]
        config_dict["Install Name"] = string_list[1]
        config_dict["Install Dir"] = string_list[2]
        config_dict["Registry Value"] = string_list[3]
        config_dict["Domain"] = string_list[7]
        config_dict["Port"] = string_list[8]
        config_dict["Network Separator"] = string_list[9]
        config_dict["Install Flag"] = string_list[6]
        
    elif string_list[6] == '0.3.6':
        config_dict["Campaign ID"] = base64.b64decode(string_list[5])
        config_dict["version"] = string_list[6]
        config_dict["Install Name"] = string_list[2]
        config_dict["Install Dir"] = string_list[3]
        config_dict["Registry Value"] = string_list[4]
        config_dict["Domain"] = string_list[8]
        config_dict["Port"] = string_list[9]
        config_dict["Network Separator"] = string_list[10]
        config_dict["Install Flag"] = string_list[11]
        
    elif  string_list[3] == '0.4.1a':
        config_dict["Campaign ID"] = base64.b64decode(string_list[2])
        config_dict["version"] = string_list[3]
        config_dict["Install Name"] = string_list[5]
        config_dict["Install Dir"] = string_list[6]
        config_dict["Registry Value"] = string_list[7]
        config_dict["Domain"] = string_list[8]
        config_dict["Port"] = string_list[9]
        config_dict["Network Separator"] = string_list[10]
        config_dict["Install Flag"] = string_list[11]

        
    elif  string_list[2] == '0.5.0E':
        config_dict["Campaign ID"] = base64.b64decode(string_list[1])
        config_dict["version"] = string_list[2]
        config_dict["Install Name"] = string_list[4]
        config_dict["Install Dir"] = string_list[5]
        config_dict["Registry Value"] = string_list[6]
        config_dict["Domain"] = string_list[7]
        config_dict["Port"] = string_list[8]
        config_dict["Network Separator"] = string_list[10]
        config_dict["Install Flag"] = string_list[9]

        
    elif  string_list[2] == '0.6.4':
        config_dict["Campaign ID"] = base64.b64decode(string_list[1])
        config_dict["version"] = string_list[2]
        config_dict["Install Name"] = string_list[3]
        config_dict["Install Dir"] = string_list[4]
        config_dict["Registry Value"] = string_list[5]
        config_dict["Domain"] = string_list[6]
        config_dict["Port"] = string_list[7]
        config_dict["Network Separator"] = string_list[8]
        config_dict["Install Flag"] = string_list[9]
        
    elif string_list[2] == '0.7.1':
        config_dict["Campaign ID"] = base64.b64decode(string_list[1])
        config_dict["version"] = string_list[2]
        config_dict["Mutex"] = string_list[3]
        config_dict["Install Name"] = string_list[4]
        config_dict["Install Dir"] = string_list[5]
        config_dict["Registry Value"] = string_list[6]
        config_dict["Domain"] = string_list[7]
        config_dict["Port"] = string_list[8]
        config_dict["Network Separator"] = string_list[10]
        config_dict["Install Flag"] = string_list[9]
        config_dict["Author"] = string_list[12]
        
    elif string_list[2] == '0.7d':
        config_dict["Campaign ID"] = base64.b64decode(string_list[1])
        config_dict["version"] = string_list[2]
        config_dict["Install Name"] = string_list[3]
        config_dict["Install Dir"] = string_list[4]
        config_dict["Registry Value"] = string_list[5]
        config_dict["Domain"] = string_list[6]
        config_dict["Port"] = string_list[7]
        config_dict["Network Separator"] = string_list[8]
        config_dict["Install Flag"] = string_list[9]
    else:
        return None
    return config_dict

def config(data):
    pe = pype32.PE(data=data) 
    string_list = get_strings(pe, 2)
    config_dict = parse_config(string_list)
    return config_dict
