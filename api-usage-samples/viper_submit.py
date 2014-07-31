#!/usr/bin/env python
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import argparse
import requests
from prettytable import PrettyTable
from progressbar import *

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
		if code == 500:
			return True
		elif code == 400:
			return True
		else:
			return False

	def find_malware(self, term, value):
		term = term.lower()
		terms = ["md5", "sha256", "ssdeep", "tag", "name", "all"]

		if not term in terms:
			print("ERROR: Invalid search term [%s]" % (", ".join(terms)))
			return

		data = {term : value}
		req = requests.post(self.build_url("/file/find"),
							data=data,
							verify=False)
		try:
			res = req.json()
		except:
			try:
				res = req.json
			except Exception as e:
				print("ERROR: Unable to parse results: {0}".format(e))
				return

		if self.check_errors(req.status_code):
			return

		if isinstance(res, dict):
			for key, value in res.items():
				if key == "tags":
					print("%s: %s" % (bold(key), ",".join(value)))
				else:
					print("%s: %s" % (bold(key), value))
		else:
			table = PrettyTable(["md5",
								 #"sha256",
								 "name",
								 "type",
								 "size",
								 "tags"])
			table.align = "l"
			table.padding_width = 1

			for entry in res:
				table.add_row([entry["md5"],
							   #entry["sha256"],
							   entry["name"],
							   entry["type"],
							   entry["size"],
							   ", ".join(entry["tags"])])

			print(table)
			print("Total: %d" % len(res))

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
	
	def get_malware(self, hash, path):
		if not os.path.exists(path):
			print("ERROR: Folder does not exist at path %s" % path)
			return

		if not os.path.isdir(path):
			print("ERROR: The path specified is not a directory.")
			return

		req = requests.get(self.build_url("/file/get/%s" % hash),
						   verify=False)

		if self.check_errors(req.status_code):
			return

		size = int(req.headers["Content-Length"].strip())
		bytes = 0

		widgets = [
			"Download: ",
			Percentage(),
			" ",
			Bar(marker=":"),
			" ",
			ETA(),
			" ",
			FileTransferSpeed()
		]
		progress = ProgressBar(widgets=widgets, maxval=size).start()

		destination = os.path.join(path, hash)
		binary = open(destination, "wb")

		for buf in req.iter_content(1024):
			if buf:
				binary.write(buf)
				bytes += len(buf)
				progress.update(bytes)

		progress.finish()
		binary.close()

		print("File downloaded at path: %s" % destination)
		
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
				print("Missing arguments (e.g. \"add <path> <comma separated tags>\")")
		elif command[0] == "find" :
			if len(command) == 3:
				self.find_malware(command[1], command[2])
			else:
				print("Missing arguments (e.g. \"find <key> <value>\")")
		elif command[0] == "get":
			if len(command) == 3:
					self.get_malware(command[1], command[2])
			else:
				print("ERROR: Missing arguments (e.g. \"get <md5|sha256> <path>\")")

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-H", "--host", help="Host of Viper API server", default=None, action="store", required=True)
	parser.add_argument("-p", "--port", help="Port of Viper API server", default=8080, action="store", required=False)
	parser.add_argument("-a", "--action", help="Action to be performed", default=None, action="store", required=True)

	args = parser.parse_args()
	
	print args

	s = Submit(host=args.host, port=args.port, action=args.action)
	s.run()

