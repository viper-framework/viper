# -*- coding: utf-8 -*-
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
    cmd = 'vttool'
    description = 'Determining the likely name of malware by querying VirusTotal'
    authors = ['robbyfux']

    def run(self):
        def logo():
            self.log('', "")
            self.log('', "  ██╗   ██╗████████╗████████╗ ██████╗  ██████╗ ██╗")
            self.log('', "  ██║   ██║╚══██╔══╝╚══██╔══╝██╔═══██╗██╔═══██╗██║")
            self.log('', "  ██║   ██║   ██║█████╗██║   ██║   ██║██║   ██║██║")
            self.log('', "  ╚██╗ ██╔╝   ██║╚════╝██║   ██║   ██║██║   ██║██║")
            self.log('', "   ╚████╔╝    ██║      ██║   ╚██████╔╝╚██████╔╝███████╗")
            self.log('', "    ╚═══╝     ╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝")
            self.log('', " Find the name of the evil")
            self.log('', "")
            
        def install():
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
        
        def usage():
            self.log('', "usage: vttool [-h] [-c]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--cluster (-c)\tStrictly lexical clustering over malware-names")
            self.log('', "")

        def wordFrequencyReport(wordCount):
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

        # Print Logo 
        logo()

        try:
            opts, argv = getopt.getopt(self.args[0:], 'hc', ['help', 'cluster'])
        except getopt.GetoptError as e:
            self.log('', e)
            return

        arg_cluster = False

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            
            if opt in ('-c', '--cluster'):
                if not HAVE_CLUSTER:
                    install()
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
                    return                        
            else:
                self.log('error', "Failed parsing the response: {0}".format(e))
                self.log('error', "Data:\n{}".format(response.content))
                return

        positives = virustotal.get("positives")
        malwarenames = []
        
        if 'scans' in virustotal:
            for engine, signature in virustotal.get("scans").items():
                if signature['detected']:
                    malwarenames.append(signature['result'])

        if malwarenames:
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
                
            # Print the Result
            wordFrequencyReport(wordCountMap)
        else:
            self.log('info', "The file does not appear to be on VirusTotal yet")
