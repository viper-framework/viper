# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import re
import os
import json
import getopt

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False
    
try:
    import numpy as np
    from fuzzywuzzy import fuzz
    from sklearn.cluster import DBSCAN
    HAVE_CLUSTER = True
except ImportError:
    HAVE_CLUSTER = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_URL_SUBMIT = 'https://www.virustotal.com/vtapi/v2/file/scan'
KEY = 'a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088'

TRENNER = [".", ":", "-", "~", "@", "!", "/", "_", ";", "[", "]", "(", ")"]

MAPPING = {" loader":"downloader",
           " risk":"riskware",
           "adware":"riskware",
           "backdoor":"trojan",
           "banker":"trojan",
           "bkdr":"trojan",
           "bundler":"riskware",
           "crypt":"ransomware",
           "cryptor":"ransomware",
           "dldr":"downloader",
           "down ":"downloader",
           "downware":"downloader",
           "grayware":"riskware",
           "hack ":"riskware",
           "hackkms":"riskware",
           "hacktool":"riskware",
           "hktl":"riskware",
           "injector":"trojan",
           "keygen":"riskware",
           "kms":"riskware",
           "krypt":"ransomware",
           "kryptik":"ransomware",
           "load ":"downloader",
           "lock":"ransomware",
           "muldown":"downloader",
           "onlinegames":"riskware",
           "ransom ":"ransomware",
           "rkit":"rootkit",
           "rogue":"riskware",
           "rogueware":"riskware",
           "rtk":"rootkit",
           "scareware":"riskware",
           "startpage":"riskware",
           "suspicious":"riskware",
           "sys":"rootkit",
           "trj":"trojan",
           "troj":"trojan",
           "unwanted":"riskware"}

REPLACE = [" tool",
           "agent",
           "application",
           "backdoor",
           "based",
           "behaves",
           "downloader",
           "dropped",
           "dropper",
           "executor",
           "exploit",
           "gen",
           "generic",
           "genome",
           "heur",
           "heuristic",
           "like",
           "malware",
           "obfuscated",
           "optional",
           "packed",
           "posible",
           "possible",
           "program",
           "ransomware",
           "reputation",
           "riskware",
           "rootkit",
           "suspect",
           "trojan",
           "unclassified",
           "unknown",
           "variant",
           "virus",
           "ware",
           "win32 ",
           "win64",
           "worm"]

def simpleWordFrequency(tmpNames):
    # find the most frequently occuring words
    wordCount = {}
    for wort in tmpNames:
        w = wort.strip()
        if len(w) > 0:
            wordCount[w] = wordCount.get(w, 0) + 1
    
    return wordCount

def normalizeMalwareNamesStep2(names):
    # sort Replace Map
    REPLACE.sort(key=lambda item:(-len(item), item))
    # delete not usable words
    for r in REPLACE:
        names = names.replace(r, " ")
    
    # delete special characters
    names = "".join(re.findall("[a-z\s]*", names))
    # delete multiple whitespaces
    names = re.sub('\s{2,}', ' ', names)
    # delete small words
    tmpNames = []
    for name in names.strip().split(' '):
        if len(name.strip()) > 3:
            tmpNames.append(name.strip())
    
    return tmpNames

def normalizeMalwareNamesStep1(malwarenames):
    # malwarenames-list to string
    names = " ".join(malwarenames)
    for trn in TRENNER:
        names = names.replace(trn, " ").lower()
    
    for key in sorted(MAPPING, key=len, reverse=True):
        names = names.replace(key, MAPPING[key])
    
    return names

# similarity from the ratio, token_sort and token_set ratio methods in FuzzyWuzzy
def computeSimilarity(s1, s2):
    return 1.0 - (0.01 * max(
        fuzz.ratio(s1, s2),
        fuzz.token_sort_ratio(s1, s2),
        fuzz.token_set_ratio(s1, s2)))
    
def uniqueList(l):
    ulist = []
    [ulist.append(x) for x in l if x not in ulist]
    return ulist

def clusterMalwareNames(malwareNames):
    # strictly lexical clustering over malware-names
    wordCount = {}
    # create a distance matrix
    matrix = np.zeros((len(malwareNames), len(malwareNames)))
    for i in range(len(malwareNames)):
        for j in range(len(malwareNames)):
            if matrix[i, j] == 0.0:        
                matrix[i, j] = computeSimilarity(malwareNames[i], malwareNames[j])
                matrix[j, i] = matrix[i, j]
    
    # Scikit-Learn's DBSCAN implementation to cluster the malware-names
    clust = DBSCAN(eps=0.1, min_samples=5, metric="precomputed")
    clust.fit(matrix)    
    
    preds = clust.labels_
    clabels = np.unique(preds)
    
    # create Word-Count Map
    for i in range(clabels.shape[0]):
        if clabels[i] < 0:
            continue
        
        cmem_ids = np.where(preds == clabels[i])[0]
        cmembers = []
        
        for cmem_id in cmem_ids:
            cmembers.append(malwareNames[cmem_id])
        
        wordCount[", ".join(uniqueList(cmembers))] = len(cmem_ids)
    return wordCount

class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal and determining the likely name of malware'
    authors = ['nex', 'robbyfux']

    def response2json(self, response):
        virustotal = None
        try:
            virustotal = response.json()
            # since python 2.7 the above line causes the Error dict object not callable
        except Exception as e:
            # workaround in case of python 2.7
            if str(e) == "'dict' object is not callable":
                try:
                    virustotal = response.json
                except Exception as e:
                    self.log('error', "Failed parsing the response: {0}".format(e))
                    self.log('error', "Data:\n{}".format(response.content))
                    raise Exception("Failed parsing the response: {0}".format(e))                        
            else:
                self.log('error', "Failed parsing the response: {0}".format(e))
                self.log('error', "Data:\n{}".format(response.content))
                raise Exception("Failed parsing the response: {0}".format(e)) 
        return virustotal

    def install(self):
        self.log('error', "Missing dependency!")
        self.log('', "")
        self.log('error', "Lexical clustering requires the following dependencies:")
        self.log('error', "numpy: http://scikit-learn.org/stable/install.html")
        self.log('error', "scikit-learn: http://scikit-learn.org/stable/install.html")
        self.log('error', "FuzzyWuzzy: https://github.com/seatgeek/fuzzywuzzy")
        self.log('error', "python-levenshtein: https://github.com/miohtama/python-Levenshtein")
        self.log('', "")
        self.log('error', "Install on Ubuntu:")
        self.log('error', " sudo apt-get -y install python-numpy python-scipy python-levenshtein")
        self.log('error', " sudo pip install beautifulsoup fuzzywuzzy scikit-learn")
        self.log('', "")

    def wordFrequencyReport(self, wordCount):
        mostFrequentWord = ''
        countWord = 0
        secWord = ''
        secCountWord = 0
        for wort, count in sorted(wordCount.iteritems(), key=lambda (k, v):(v, k)):
            if count > countWord:
                secWord = mostFrequentWord
                secCountWord = countWord
                mostFrequentWord = wort
                countWord = count
        
        self.log('', '--- scanner malware family determination ---')
        self.log('', "Most frequent word: %s (count=%d)" % (mostFrequentWord, countWord))
        if secCountWord > 0:
            self.log('', "Second most frequent word: %s (count=%d)" % (secWord, secCountWord))
        self.log('', '')

    def run(self):
            
        def usage():
            self.log('', "usage: virustotal [-h] [-n] [-c] [-s]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--name (-n)\tDetermining the likely name of malware")
            self.log('', "\t--cluster (-c)\tStrictly lexical clustering over malware-names")
            self.log('', "\t--submit (-s)\tSubmit file to VirusTotal (by default it only looks up the hash)")
            self.log('', "")

        arg_submit = False
        arg_cluster = False
        arg_name = False

        try:
            opts, argv = getopt.getopt(self.args[0:], 'hncs', ['help', 'submit', 'name', 'cluster'])
        except getopt.GetoptError as e:
            self.log('', e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--submit'):
                arg_submit = True
            elif opt in ('-n', '--name'):
                arg_name = True            
            elif opt in ('-c', '--cluster'):
                if not HAVE_CLUSTER:
                    self.install()
                    return
                arg_cluster = True

        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        data = {'resource' : __sessions__.current.file.md5, 'apikey' : KEY}

        try:
            response = requests.post(VIRUSTOTAL_URL, data=data)
        except Exception as e:
            self.log('error', "Failed performing request: {0}".format(e))
            return

        try:
            virustotal = self.response2json(response)
        except:
            return      
        
        rows = []
        if 'scans' in virustotal:
            for engine, signature in virustotal['scans'].items():
                if signature['detected']:
                    signature = signature['result']
                else:
                    signature = ''
                rows.append([engine, signature])

        if not rows:
            self.log('info', "The file does not appear to be on VirusTotal yet")
        elif arg_name or arg_cluster:  # Determining the likely name of malware
            malwarenames = []
            
            if rows:
                # Get malwarenames from rows-list 
                [malwarenames.append(x[1]) for x in rows if x[1]]

                # Normalize Step 1
                names = normalizeMalwareNamesStep1(malwarenames)
                
                self.log('', '--- scanner malware classification ---')
                self.log('', 'ransomware: ' + str(names.count("ransomware")))
                self.log('', '   dropper: ' + str(names.count("dropper")))
                self.log('', '   exploit: ' + str(names.count("exploit")))
                self.log('', 'downloader: ' + str(names.count("downloader")))
                self.log('', '  riskware: ' + str(names.count("riskware")))
                self.log('', '   rootkit: ' + str(names.count("rootkit")))
                self.log('', '      worm: ' + str(names.count("worm")))
                self.log('', '    trojan: ' + str(names.count("trojan")))
                self.log('', "")
                
                # Normalize Step 2
                names = normalizeMalwareNamesStep2(names)
                
                # create Word-Count-Map
                if arg_cluster:
                    # strictly lexical clustering over malware-names
                    wordCountMap = clusterMalwareNames(names)
                else:
                    wordCountMap = simpleWordFrequency(names)
                
                positives = virustotal.get("positives")
                total = virustotal.get("total")
                
                self.log('', '--- detection rate ---')
                self.log('', 'totalscanner: %d' % total)
                self.log('', '   positives: %d' % positives)
                self.log('', "")                
                    
                # Print the Result
                self.wordFrequencyReport(wordCountMap)                
        elif arg_submit: # Submit file
            if rows:
                self.log('', "")
                self.log('info', "The file is already available on VirusTotal, no need to submit")
                return
            try:
                data = {'apikey' : KEY}
                files = {'file' : open(__sessions__.current.file.path, 'rb').read()}
                response = requests.post(VIRUSTOTAL_URL_SUBMIT, data=data, files=files)
            except Exception as e:
                self.log('error', "Failed Submit: {0}".format(e))
                return

            try:
                virustotal = self.response2json(response)
            except:
                return

            if 'verbose_msg' in virustotal:
                self.log('info', "{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))
        else: # Print VirusTotal scanner result table
            rows.sort()
            if rows:
                self.log('info', "VirusTotal Report:")
                self.log('table', dict(header=['Antivirus', 'Signature'], rows=rows))
