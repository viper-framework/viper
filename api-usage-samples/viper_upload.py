#!/usr/bin/env python
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import argparse
import requests

class Submit(object):
	def __init__(self, host, port, action):
		self.host = host
		self.port = port
		self.action = action

	def build_url(self, route):
		url = "http://"
		url += "%s:%s%s" % (self.host, self.port, route)
		return url
	
	def check_errors(self, code):
		print code

		return False

	def add_malware(self, path, tags=None):
		if not os.path.exists(path):
			print("ERROR: File does not exist %s" % path)
			return
	
		files = {"file": (os.path.basename(path), open(path, "rb"))}
		data = {"tags" : tags}	

		req = requests.post(self.build_url("/file/add"),
				verify=False,
				files=files,
				data=data)
	
		if not self.check_errors(req.status_code):
			print("File uploaded successfully")
	
	def run(self):
		command = self.action.strip().split(" ")

		if command[0] == "add" :
			# sample:
			# viper_upload.py --host ... -a "add <file> <tag, tag, ...>"
			if len(command) == 2:
				self.add_malware(command[1])
			elif len(command) == 3:
				self.add_malware(command[1], command[2])
			else:
				print("Missing arguments (e.g. \"add <path> <comma separated tags\")")
		
		
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-H", "--host", help="Host of Viper API server", default=None, action="store", required=True)
	parser.add_argument("-p", "--port", help="Port of Viper API server", default=8080, action="store", required=False)
	parser.add_argument("-a", "--action", help="Action to be performed", default=None, action="store", required=True)

	args = parser.parse_args()
	
	print args

	s = Submit(host=args.host, port=args.port, action=args.action)
	s.run()

