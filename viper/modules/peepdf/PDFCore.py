#
#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2014 Jose Miguel Esparza
#
#    This file is part of peepdf.
#
#        peepdf is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf.    If not, see <http://www.gnu.org/licenses/>.
#

'''
    This module contains classes and methods to analyse and modify PDF files
'''

import sys,os,re,hashlib,struct,aes as AES
from PDFUtils import *
from PDFCrypto import *
from JSAnalysis import *
from PDFFilters import decodeStream,encodeStream

MAL_ALL = 1
MAL_HEAD = 2
MAL_EOBJ = 3
MAL_ESTREAM = 4
MAL_XREF = 5
MAL_BAD_HEAD = 6
pdfFile = None
newLine = os.linesep
isForceMode = False
isManualAnalysis = False
spacesChars = ['\x00','\x09','\x0a','\x0c','\x0d','\x20']
delimiterChars = ['<<','(','<','[','{','/','%']
monitorizedEvents = ['/OpenAction ','/AA ','/Names ','/AcroForm ', '/XFA ']
monitorizedActions = ['/JS ','/JavaScript','/Launch','/SubmitForm','/ImportData']
monitorizedElements = ['/EmbeddedFiles ',
                       '/EmbeddedFile',
                       '/JBIG2Decode',
                       'getPageNthWord',
                       'arguments.callee',
                       '/U3D',
                       '/PRC',
                       '/RichMedia',
                       '.rawValue',
                       'keep.previous']
jsVulns = ['mailto',
           'Collab.collectEmailInfo',
           'util.printf',
           'getAnnots',
           'getIcon',
           'spell.customDictionaryOpen',
           'media.newPlayer',
           'doc.printSeps',
           'app.removeToolButton']
singUniqueName = 'CoolType.SING.uniqueName'
bmpVuln = 'BMP/RLE heap corruption'
vulnsDict = {'mailto':('mailto',['CVE-2007-5020']),
             'Collab.collectEmailInfo':('Collab.collectEmailInfo',['CVE-2007-5659']),
             'util.printf':('util.printf',['CVE-2008-2992']),
             '/JBIG2Decode':('Adobe JBIG2Decode Heap Corruption',['CVE-2009-0658']),
             'getIcon':('getIcon',['CVE-2009-0927']),
             'getAnnots':('getAnnots',['CVE-2009-1492']),
             'spell.customDictionaryOpen':('spell.customDictionaryOpen',['CVE-2009-1493']),
             'media.newPlayer':('media.newPlayer',['CVE-2009-4324']),
             '.rawValue':('Adobe Acrobat Bundled LibTIFF Integer Overflow',['CVE-2010-0188']),
             singUniqueName:(singUniqueName,['CVE-2010-2883']),
             'doc.printSeps':('doc.printSeps',['CVE-2010-4091']),
             '/U3D':('/U3D',['CVE-2009-3953','CVE-2009-3959','CVE-2011-2462']),
             '/PRC':('/PRC',['CVE-2011-4369']),
             'keep.previous':('Adobe Reader XFA oneOfChild Un-initialized memory vulnerability',['CVE-2013-0640']), # https://labs.portcullis.co.uk/blog/cve-2013-0640-adobe-reader-xfa-oneofchild-un-initialized-memory-vulnerability-part-1/
             bmpVuln:(bmpVuln,['CVE-2013-2729']),
             'app.removeToolButton':('app.removeToolButton',['CVE-2013-3346'])}
jsContexts = {'global':None}

class PDFObject :
    '''
        Base class for all the PDF objects
    '''
    def __init__(self, raw = None):
        '''
            Constructor of a PDFObject
            
            @param raw: The raw value of the PDF object
        '''
        self.references = []
        self.type = ''
        self.value = ''
        self.rawValue = raw
        self.JSCode = []
        self.updateNeeded = False
        self.containsJScode = False
        self.encryptedValue = raw
        self.encryptionKey = ''
        self.encrypted = False
        self.errors = []
        self.referencesInElements = {}
        self.compressedIn = None
    
    def addError(self, errorMessage):
        '''
            Add an error to the object
            
            @param errorMessage: The error message to be added (string)
        '''
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)
            
    def contains(self, string):
        '''
            Look for the string inside the object content
            
            @param string: A string
            @return: A boolean to specify if the string has been found or not
        '''
        value = str(self.value)
        rawValue = str(self.rawValue)
        encValue = str(self.encryptedValue)
        if re.findall(string,value,re.IGNORECASE) != [] or re.findall(string,rawValue,re.IGNORECASE) != [] or re.findall(string,encValue,re.IGNORECASE) != []:
            return True
        if self.containsJS():
            for js in self.JSCode:
                if re.findall(string,js,re.IGNORECASE) != []:
                    return True
        return False

    def containsJS(self):
        '''
            Method to check if there are Javascript code inside the object
            
            @return: A boolean
        '''
        return self.containsJScode

    def encodeChars(self):
        '''
            Encode the content of the object if possible (only for PDFName, PDFString, PDFArray and PDFStreams) 
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        return (0,'')
    
    def encrypt(self, password):
        '''
            Encrypt the content of the object if possible 
            
            @param password: The password used to encrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        return (0,'')

    def getCompressedIn(self):
        '''
            Gets the id of the object (object stream) where the actual object is compressed 
            
            @return: The id (int) of the object stream or None if it's not compressed
        '''
        return self.compressedIn
                    
    def getEncryptedValue(self):
        '''
            Gets the encrypted value of the object 
            
            @return: The encrypted value or the raw value if the object is not encrypted
        '''
        return self.encryptedValue    

    def getEncryptionKey(self):
        '''
            Gets the encryption key (password) used to encrypt the object 
            
            @return: The password (string) or an empty string if it's not encrypted
        '''
        return self.encryptionKey

    def getErrors(self):
        '''
            Gets the error messages found while parsing and processing the object 
            
            @return: The array of errors of the object
        '''
        return self.errors

    def getRawValue(self):
        '''
            Gets the raw value of the object 
            
            @return: The raw value of the object, this means without applying filters or decoding characters
        '''
        return self.rawValue

    def getReferences(self):
        '''
            Gets the referenced objects in the actual object 
            
            @return: An array of references in the object (Ex. ['1 0 R','12 0 R'])
        '''
        return self.references
    
    def getReferencesInElements(self):
        '''
            Gets the dependencies between elements in the object and objects in the rest of the document.
            
            @return: A dictionary of dependencies of the object (Ex. {'/Length':[5,'']} or {'/Length':[5,'354']})
        '''
        return self.referencesInElements

    def getStats(self):
        '''
            Gets the statistics of the object 
            
            @return: An array of different statistics of the object (object type, compression, references, etc)
        '''
        stats = {}
        stats['Object'] = self.type
        stats['MD5'] = hashlib.md5(self.value).hexdigest()
        stats['SHA1'] = hashlib.sha1(self.value).hexdigest()
        if self.isCompressed():
            stats['Compressed in'] = str(self.compressedIn)
        else:
            stats['Compressed in'] = None
        stats['References'] = str(self.references)
        if self.containsJScode:
            stats['JSCode'] = True
            if len(self.unescapedBytes) > 0:
                stats['Escaped Bytes'] = True
            else:
                stats['Escaped Bytes'] = False
            if len(self.urlsFound) > 0:
                stats['URLs'] = True
            else:
                stats['URLs'] = False
        else:
            stats['JSCode'] = False
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        return stats
        
    def getType(self):
        '''
            Gets the type of the object 
            
            @return: The object type (bool, null, real, integer, name, string, hexstring, reference, array, dictionary, stream)
        '''
        return self.type

    def getValue(self):
        '''
            Gets the value of the object 
            
            @return: The value of the object, this means after applying filters and/or decoding characters and strings
        '''
        return self.value    

    def isCompressed(self):
        '''
            Specifies if the object is compressed or not 
            
            @return: A boolean
        '''
        if self.compressedIn != None:
            return True
        else:
            return False
                
    def isEncrypted(self):
        '''
            Specifies if the object is encrypted or not 
            
            @return: A boolean
        '''
        return self.encrypted

    def isFaulty(self):
        '''
            Specifies if the object has errors or not 
            
            @return: A boolean
        '''
        if self.errors == []:
            return False
        else:
            return True
    
    def replace(self, string1, string2):
        '''
            Searches the object for the 'string1' and if it's found it's replaced by 'string2' 
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        if self.value.find(string1) == -1 and self.rawValue.find(string1) == -1:
            return (-1,'String not found')
        self.value = self.value.replace(string1, string2)
        self.rawValue = self.rawValue.replace(string1, string2)
        ret = self.update()
        return ret
    
    def resolveReferences(self):
        '''
            Replaces the reference to an object by its value if there are references not resolved. Ex. /Length 3 0 R 
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        pass

    def setCompressedIn(self, id):
        '''
            Sets the object id of the object stream containing the actual object
            
            @param id: The object id (int)
        '''
        self.compressedIn = id

    def setEncryptedValue(self, value):
        '''
            Sets the encrypted value of the object
            
            @param value: The encrypted value (string) 
        '''
        self.encryptedValue = value
        
    def setEncryptionKey(self, password):
        '''
            Sets the password to encrypt/decrypt the object
            
            @param password: The encryption key (string)  
        '''
        self.encryptionKey = password

    def setRawValue(self, newRawValue):
        '''
            Sets the raw value of the object and updates the object if some modification is needed
            
            @param newRawValue: The new raw value (string)
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.rawValue = newRawValue
        ret = self.update()
        return ret
    
    def setReferencesInElements(self, resolvedReferencesDict):
        '''
            Sets the resolved references array
            
            @param resolvedReferencesDict: A dictionary with the resolved references  
        '''
        self.referencesInElements = resolvedReferencesDict

    def setValue(self, newValue):
        '''
            Sets the value of the object
            
            @param newValue: The new value of the object (string)  
        '''
        self.value = newValue
            
    def update(self):
        '''
            Updates the object after some modification has occurred
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.encryptedValue = self.rawValue
        return (0,'')

    def toFile(self):
        '''
            Gets the raw or encrypted value of the object to write it to an output file 
            
            @return: The raw/encrypted value of the object (string)
        '''
        if self.encrypted:
            return self.getEncryptedValue()
        else:
            return self.getRawValue()


class PDFBool (PDFObject) :
    '''
        Boolean object of a PDF document
    '''
    def __init__(self, value) :
        self.type = 'bool'
        self.errors = []
        self.references = []
        self.JSCode = []
        self.encrypted = False
        self.updateNeeded = False
        self.containsJScode = False
        self.referencesInElements = {}
        self.value = self.rawValue = self.encryptedValue = value
        self.compressedIn = None


class PDFNull (PDFObject) :
    '''
        Null object of a PDF document
    '''
    def __init__(self, content) :
        self.type = 'null'
        self.errors = []
        self.JSCode = []
        self.compressedIn = None
        self.encrypted = False
        self.value = self.rawValue = self.encryptedValue = content
        self.updateNeeded = False
        self.containsJScode = False
        self.referencesInElements = {}
        self.references = []


class PDFNum (PDFObject) :
    '''
        Number object of a PDF document: can be an integer or a real number.
    '''
    def __init__(self, num) :
        self.errors = []
        self.JSCode = []
        self.compressedIn = None
        self.encrypted = False
        self.value = num
        self.compressedIn = None
        self.updateNeeded = False
        self.containsJScode = False
        self.referencesInElements = {}
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if isForceMode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
    
    def replace(self, string1, string2):
        if self.value.find(string1) == -1:
            return (-1,'String not found')
        self.value = self.value.replace(string1, string2)
        ret = self.update()
        return ret
        
    def update(self):
        self.errors = []
        try:
            if self.value.find('.') != -1:
                self.type = 'real'
                self.rawValue = float(self.value)
            else:
                self.type = 'integer'
                self.rawValue = int(self.value)
        except:
            errorMessage = 'Numeric conversion error'
            self.addError(errorMessage)
            return (-1,errorMessage)
        self.encryptedValue = str(self.rawValue)
        return (0,'')
            
    def setRawValue(self, rawValue):
        self.rawValue = rawValue
        
    def setValue(self, value):
        self.value = value
        ret = self.update()
        return ret
    
    def toFile(self):
        return str(self.rawValue)


class PDFName (PDFObject) :
    '''
        Name object of a PDF document
    '''
    def __init__(self, name) :
        self.type = 'name'
        self.errors = []
        self.JSCode = []
        self.references = []
        self.compressedIn = None
        if name[0] == '/':
            self.rawValue = self.value = self.encryptedValue = name
        else:
            self.rawValue = self.value = self.encryptedValue = '/' + name
        self.updateNeeded = False
        self.containsJScode = False
        self.encryptedValue = ''
        self.encrypted = False
        self.referencesInElements = {}
        ret = self.update()
        if ret[0] == -1:
            if isForceMode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])

    def update(self):
        self.errors = []
        errorMessage = ''
        self.value = self.rawValue
        self.encryptedValue = self.rawValue
        hexNumbers = re.findall('#([0-9a-f]{2})', self.value, re.DOTALL | re.IGNORECASE)
        try:
            for hexNumber in hexNumbers:
                self.value = self.value.replace('#' + hexNumber, chr(int(hexNumber,16)))
        except:
            errorMessage = 'Error in hexadecimal conversion'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return (0,'')

    def encodeChars(self):
        ret = encodeName(self.value)
        if ret[0] == -1:
            self.addError(ret[1])
            return ret
        else:
            self.rawValue = ret[1]
            return (0,'')


class PDFString (PDFObject) :
    '''
        String object of a PDF document
    '''
    def __init__(self, string) :
        self.type = 'string'
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.value = self.rawValue = self.encryptedValue = string
        self.updateNeeded = False
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.references = []
        self.referencesInElements = {}
        ret = self.update()
        if ret[0] == -1:
            if isForceMode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
        
    def update(self, decrypt = False):
        '''
            Updates the object after some modification has occurred
            
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.errors = []
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.rawValue = unescapeString(self.rawValue)
        self.value = self.rawValue
        '''
        self.value = self.value.replace('\)',')')
        self.value = self.value.replace('\\\\','\\')
        self.value = self.value.replace('\\\r\\\n','')
        self.value = self.value.replace('\\\r','')
        self.value = self.value.replace('\\\n','')
        '''
        octalNumbers = re.findall('\\\\([0-7]{1,3})', self.value, re.DOTALL)
        try:
            for octal in octalNumbers:
                #TODO: check!! \\\\?
                self.value = self.value.replace('\\' + octal, chr(int(octal,8)))
        except:
            errorMessage = 'Error in octal conversion'
            self.addError(errorMessage)
            return (-1,errorMessage)
        if isJavascript(self.value):
            self.containsJScode = True
            self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.value, jsContexts['global'], isManualAnalysis)
            if jsErrors != []:
                for jsError in jsErrors:
                    errorMessage = 'Error analysing Javascript: '+jsError
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
        if self.encrypted and not decrypt:
            ret = self.encrypt()
            if ret[0] == -1:
                return ret
        return (0,'')

    def encodeChars(self):
         ret = encodeString(self.value)
         if ret[0] == -1:
             self.addError(ret[1])
             return ret
         else:
             self.rawValue = ret[1]
             return (0,'')
    
    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        try:
            self.encryptedValue = RC4(self.rawValue,self.encryptionKey)
        except:
            errorMessage = 'Error encrypting with RC4'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return (0,'')

    def decrypt(self, password = None, algorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        try:
            cleanString = unescapeString(self.encryptedValue)
            if algorithm == 'RC4':
                self.rawValue = RC4(cleanString,self.encryptionKey)
            elif algorithm == 'AES':
                ret = AES.decryptData(cleanString,self.encryptionKey)
                if ret[0] != -1:
                    self.rawValue = ret[1]
                else:
                    errorMessage = 'AES decryption error: '+ret[1]
                    self.addError(errorMessage)
                    return (-1,errorMessage)
        except:
            errorMessage = 'Error decrypting with '+str(algorithm)
            self.addError(errorMessage)
            return (-1,errorMessage)
        ret = self.update(decrypt = True)
        return (0,'')
    
    def getEncryptedValue(self):
        return '('+escapeString(self.encryptedValue)+')'
    
    def getJSCode(self):
        '''
            Gets the Javascript code of the object 
            
            @return: An array of Javascript code sections
        '''
        return self.JSCode    
    
    def getRawValue(self):
        return '('+escapeString(self.rawValue)+')'
    
    def getUnescapedBytes(self):
        '''
            Gets the escaped bytes of the object unescaped 
            
            @return: An array of unescaped bytes (string)
        '''
        return self.unescapedBytes
    
    def getURLs(self):
        '''
            Gets the URLs of the object 
            
            @return: An array of URLs
        '''
        return self.urlsFound


class PDFHexString (PDFObject) :
    '''
        Hexadecimal string object of a PDF document
    '''
    def __init__(self, hex) : 
        self.asciiValue = ''
        self.type = 'hexstring'
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.value = '' # Value after hex decoding and decryption
        self.rawValue = hex # Hex characters
        self.encryptedValue = hex # Value after hex decoding
        self.updateNeeded = False
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.referencesInElements = {}
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if isForceMode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])        
            
    def update(self, decrypt = False, newHexValue = True):
        '''
            Updates the object after some modification has occurred
            
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.errors = []
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        if not decrypt:
            try:
                if newHexValue:
                    # New hexadecimal value
                    self.value = ''
                    tmpValue = self.rawValue
                    if len(tmpValue) % 2 != 0:
                        tmpValue += '0'
                    self.value = tmpValue.decode('hex')
                else:
                    # New decoded value
                    self.rawValue = self.value.encode('hex')
                self.encryptedValue = self.value
            except:
                errorMessage = 'Error in hexadecimal conversion'
                self.addError(errorMessage)
                return (-1,errorMessage)
        if isJavascript(self.value):
            self.containsJScode = True
            self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.value, jsContexts['global'], isManualAnalysis)
            if jsErrors != []:
                for jsError in jsErrors:
                    errorMessage = 'Error analysing Javascript: '+jsError
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
        if self.encrypted and not decrypt:
            ret = self.encrypt()
            if ret[0] == -1:
                return ret
        return (0,'')

    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        try:
            self.encryptedValue = RC4(self.value,self.encryptionKey)
            self.rawValue = self.encryptedValue.encode('hex')
        except:
            errorMessage = 'Error encrypting with RC4'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return (0,'')
    
    def decrypt(self, password = None, algorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        try:
            cleanString = unescapeString(self.encryptedValue)
            if algorithm == 'RC4':
                self.value = RC4(cleanString,self.encryptionKey)
            elif algorithm == 'AES':
                ret = AES.decryptData(cleanString,self.encryptionKey)
                if ret[0] != -1:
                    self.value = ret[1]
                else:
                    errorMessage = 'AES decryption error: '+ret[1]
                    self.addError(errorMessage)
                    return (-1,errorMessage)
        except:
            errorMessage = 'Error decrypting with '+str(algorithm)
            self.addError(errorMessage)
            return (-1,errorMessage)
        ret = self.update(decrypt = True)
        return ret

    def getEncryptedValue(self):
        return '<'+self.rawValue+'>'

    def getJSCode(self):
        '''
            Gets the Javascript code of the object 
            
            @return: An array of Javascript code sections
        '''
        return self.JSCode

    def getRawValue(self):
        return '<'+self.rawValue+'>'

    def getUnescapedBytes(self):
        '''
            Gets the escaped bytes of the object unescaped 
            
            @return: An array of unescaped bytes (string)
        '''
        return self.unescapedBytes
    
    def getURLs(self):
        '''
            Gets the URLs of the object 
            
            @return: An array of URLs
        '''
        return self.urlsFound


class PDFReference (PDFObject) :
    '''
        Reference object of a PDF document
    '''
    def __init__(self, id, genNumber = '0') :
        self.type = 'reference'
        self.errors = []
        self.JSCode = []
        self.compressedIn = None
        self.encrypted = False
        self.value = self.rawValue = self.encryptedValue = id + ' ' + genNumber + ' R'
        self.id = id
        self.genNumber = genNumber
        self.updateNeeded = False
        self.containsJScode = False
        self.referencesInElements = {}
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if isForceMode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
        
    def update(self):
        self.errors = []
        self.value = self.encryptedValue = self.rawValue
        valueElements = self.rawValue.split()
        if valueElements != []:
            self.id = int(valueElements[0])
            self.genNumber = int(valueElements[1])
        else:
            errorMessage = 'Error getting PDFReference elements'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return (0,'')
    
    def getGenNumber(self):
        '''
            Gets the generation number of the reference
            
            @return: The generation number (int)
        '''
        return self.genNumber
    
    def getId(self):
        '''
            Gets the object id of the reference
            
            @return: The object id (int)
        '''
        return self.id
    
    def setGenNumber(self, newGenNumber):
        '''
            Sets the generation number of the reference
            
            @param newGenNumber: The new generation number (int)
        '''
        self.genNumber = newGenNumber

    def setId(self, newId):
        '''
            Sets the object id of the reference
            
            @param newId: The new object id (int)
        '''
        self.id = newId


class PDFArray (PDFObject) :
    '''
        Array object of a PDF document
    '''
    def __init__(self, rawContent = '', elements = []) :
        self.type = 'array'
        self.errors = []
        self.JSCode = []
        self.compressedIn = None
        self.encrypted = False
        self.encryptedValue = rawContent
        self.rawValue = rawContent
        self.elements = elements
        self.value = ''
        self.updateNeeded = False
        self.containsJScode = False
        self.referencesInElements = {}
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if isForceMode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])

    def update(self, decrypt = False):
        '''
            Updates the object after some modification has occurred
            
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        errorMessage = ''
        self.errors = []
        self.encryptedValue = '[ '
        self.rawValue = '[ '
        self.value = '[ '
        self.references = []
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        for element in self.elements:
            if element != None:
                type = element.getType()
                if type == 'reference':
                    self.references.append(element.getValue())
                elif type == 'dictionary' or type == 'array':
                    self.references += element.getReferences()
                if element.containsJS():
                    self.containsJScode = True
                    self.JSCode += element.getJSCode()
                    self.unescapedBytes += element.getUnescapedBytes()
                    self.urlsFound += element.getURLs()
                if element.isFaulty():
                    for error in valueObject.getErrors():
                        self.addError('Children element contains errors: ' + error)
                if type in ['string','hexstring','array','dictionary'] and self.encrypted and not decrypt:
                    ret = element.encrypt(self.encryptionKey)
                    if ret[0] == -1:
                        errorMessage = 'Error encrypting element'
                        self.addError(errorMessage)
                self.encryptedValue += str(element.getEncryptedValue()) + ' '
                self.rawValue += str(element.getRawValue()) + ' '
                self.value += element.getValue() + ' '
            else:
                errorMessage = 'None elements'
                self.addError(errorMessage)
        self.encryptedValue = self.encryptedValue[:-1] + ' ]'
        self.rawValue = self.rawValue[:-1] + ' ]'
        self.value = self.value[:-1] + ' ]'
        if errorMessage != '':
            return (-1,'Errors while updating PDFArray')
        else:
            return (0,'')
        
    def addElement(self, element):
        '''
            Adds an element to the array
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.elements.append(element)
        ret = self.update()
        return ret
        
    def decrypt(self, password = None, algorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''  
        errorMessage = ''
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        decryptedElements = []
        for element in self.elements:
            if element != None:
                type = element.getType()
                if type in ['string','hexstring','array','dictionary']:
                    ret = element.decrypt(self.encryptionKey, algorithm)
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(errorMessage)
                decryptedElements.append(element)
        self.elements = decryptedElements
        ret = self.update(decrypt = True)
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret

    def encodeChars(self):
        errorMessage = ''
        encodedElements = []
        for element in self.elements:
            if element != None:
                type = element.getType()
                if type in ['string','name','array','dictionary']:
                    ret = element.encodeChars()
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(errorMessage)
                encodedElements.append(element)
        self.elements = encodedElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
        
    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        ret = self.update()
        return ret
        
    def getElementByName(self, name):
        '''
            Gets the dictionary elements with the given name
            
            @param name: The name
            @return: An array of elements
        '''
        retElements = []
        for element in self.elements:
            if element != None:
                if element.getType() == 'dictionary' or element.getType() == 'array':
                    retElements += element.getElementByName(name)
            else:
                errorMessage = 'None elements'
                self.addError(errorMessage)
        return retElements
    
    def getElementRawValues(self):
        '''
            Gets the raw values of each element
            
            @return: An array of values
        '''
        values = []
        for element in self.elements:
            if element != None:
                values.append(element.getRawValue())
            else:
                values.append(None)
                errorMessage = 'None elements'
                self.addError(errorMessage)
        return values

    def getElementValues(self):
        '''
            Gets the values of each element
            
            @return: An array of values
        '''
        values = []
        for element in self.elements:
            if element != None:
                values.append(element.getValue())
            else:
                values.append(None)
                errorMessage = 'None elements'
                self.addError(errorMessage)
        return values

    def getElements(self):
        '''
            Gets the elements of the array object
            
            @return: An array of PDFObject elements
        '''
        return self.elements

    def getNumElements(self):
        '''
            Gets the number of elements of the array
            
            @return: The number of elements (int)
        '''
        return len(self.elements)

    def hasElement(self, name):
        '''
            Specifies if the array contains the element with the given name
            
            @param name: The element
            @return: A boolean
        '''
        for element in self.elements:
            if element != None:
                if element.getType() == 'dictionary':
                    if element.hasElement(name):
                        return True
                elif element.getValue() == name:
                    return True
            else:
                errorMessage = 'None elements'
                self.addError(errorMessage)
        else:
            return False

    def replace(self, string1, string2):
        errorMessage = ''
        stringFound = False
        newElements = []
        if self.rawValue.find(string1) != -1:
            self.rawValue = self.rawValue.replace(string1, string2)
            stringFound = True
            if errorMessage == 'String not found':
                errorMessage = ''
        for element in self.elements:
            if element != None:
                ret = element.replace(string1, string2)
                if ret[0] == -1:
                    if ret[1] != 'String not found' or not stringFound:
                        errorMessage = ret[1]
                else:
                    stringFound = True
                    if errorMessage == 'String not found':
                        errorMessage = ''
                newElements.append(element)
            else:
                errorMessage = 'None element while replacing strings'
                self.addError('None element')
        if not stringFound:
            return (-1,'String not found')
        self.elements = newElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
    
    def setElements(self, newElements):
        '''
            Sets the array of elements
            
            @param newElements: The new array of elements
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.elements = newElements
        ret = self.update()
        return ret


class PDFDictionary (PDFObject):
    def __init__(self, rawContent = '', elements = {}, rawNames = {}) :
        self.type = 'dictionary'
        self.dictType = ''
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.value = ''
        self.updateNeeded = False
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.referencesInElements = {}
        self.rawValue = rawContent
        self.encryptedValue = rawContent
        self.rawNames = rawNames
        self.elements = elements
        self.numElements = len(self.elements)
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if isForceMode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
    
    def update(self, decrypt = False):
        '''
            Updates the object after some modification has occurred
            
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.errors = []
        self.references = []
        self.containsJScode = False
        self.JSCode = []
        self.dictType = ''
        self.unescapedBytes = []
        self.urlsFound = []
        errorMessage = ''
        self.value = '<< '
        self.rawValue = '<< '
        self.encryptedValue = '<< '
        keys = self.elements.keys()
        values = self.elements.values()
        for i in range(len(keys)):
            if values[i] == None:
                errorMessage = 'Non-existing value for key "'+str(keys[i])+'"'
                if isForceMode:
                    self.addError(errorMessage)
                    valueObject = PDFString('')
                else:
                    return (-1,errorMessage)
            else:
                valueObject = values[i]
            v = valueObject.getValue()
            type = valueObject.getType()
            if keys[i] == '/Type':
                self.dictType = v
            elif keys[i] == '/S':
                if self.dictType == '':
                    self.dictType = '/Action ' + v
                else:
                    self.dictType += ' ' + v
            if type == 'reference':
                self.references.append(v)
            elif type == 'dictionary' or type == 'array':
                self.references += valueObject.getReferences()
            if valueObject.containsJS():
                self.containsJScode = True
                self.JSCode += valueObject.getJSCode()
                self.unescapedBytes += valueObject.getUnescapedBytes()
                self.urlsFound += valueObject.getURLs()
            if valueObject.isFaulty():
                for error in valueObject.getErrors():
                    self.addError('Children element contains errors: ' + error)
            if self.rawNames.has_key(keys[i]):
                rawName = self.rawNames[keys[i]]
                rawValue = rawName.getRawValue()
            else:
                rawValue = keys[i]
                self.rawNames[keys[i]] = PDFName(keys[i][1:])
            if type in ['string','hexstring','array','dictionary'] and self.encrypted and not decrypt:
                ret = valueObject.encrypt(self.encryptionKey)
                if ret[0] == -1:
                    errorMessage = 'Error encrypting element'
                    self.addError(errorMessage)
            self.encryptedValue += rawValue + ' ' + str(valueObject.getEncryptedValue()) + newLine
            self.rawValue += rawValue + ' ' + str(valueObject.getRawValue()) + newLine
            self.value += keys[i] + ' ' + v + newLine
        self.encryptedValue = self.encryptedValue[:-1] + ' >>'
        self.rawValue = self.rawValue[:-1] + ' >>'
        self.value = self.value[:-1] + ' >>'
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,'')
                
    def decrypt(self, password = None, algorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.encrypted = True
        errorMessage = ''
        if password != None:
            self.encryptionKey = password
        decryptedElements = {}
        for key in self.elements:
            object = self.elements[key]
            objectType = object.getType()
            if objectType in ['string','hexstring','array','dictionary']:
                ret = object.decrypt(self.encryptionKey, algorithm)
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(errorMessage)
            decryptedElements[key] = object
        self.elements = decryptedElements
        ret = self.update(decrypt = True)
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
    
    def delElement(self, name, update = True):
        '''
            Removes the element from the dictionary
            
            @param name: The element to remove
            @param update: A boolean indicating if it's necessary an update of the object. By default: True.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        if self.elements.has_key(name):
            del(self.elements[name])
            if update:
                ret = self.update()
                return ret
            return (0,'')
        else:
            return (-1,'Element not found')

    def encodeChars(self):
        encodedElements = {}
        errorMessage = ''
        for key in self.elements:
            rawName = self.rawNames[key]
            rawName.encodeChars()
            self.rawNames[key] = rawName
            object = self.elements[key]
            objectType = object.getType()
            if objectType in ['string','name','array','dictionary']:
                ret = object.encodeChars()
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(errorMessage)
            encodedElements[key] = object
        self.elements = encodedElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
        
    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        ret = self.update()
        return ret

    def getDictType(self):
        '''
            Gets the type of dictionary
            
            @return: The dictionary type (string)
        '''
        return self.dictType

    def getElement(self, name):
        '''
            Gets the element of the dictionary with the given name
           
            @param name: The name of element
            @return: The PDFObject or None if it's not found
        '''
        if self.elements.has_key(name):
            return self.elements[name]
        else:
            return None

    def getElementByName(self, name, recursive = False):
        '''
            Gets the elements with the given name
            
            @param name: The name
            @param recursive: A boolean indicating if the search is recursive or not. By default: False.
            @return: A PDFObject if recursive = False and an array of PDFObjects if recursive = True.
        '''
        retElements = []
        if self.elements.has_key(name):
            if recursive:
                retElements.append(self.elements[name])
            else:
                return self.elements[name]
        if recursive:
            for element in self.elements.values():
                if element != None and (element.getType() == 'dictionary' or element.getType() == 'array'):
                    retElements += element.getElementByName(name)
        return retElements
    
    def getElements(self):
        '''
            Gets the elements of the array object
            
            @return: An array of PDFObject elements
        '''
        return self.elements
        
    def getJSCode(self):
        '''
            Gets the Javascript code of the object 
            
            @return: An array of Javascript code sections
        '''
        return self.JSCode
    
    def getNumElements(self):
        '''
            Gets the number of elements of the array
            
            @return: The number of elements (int)
        '''
        return len(self.elements)    

    def getStats(self):
        stats = {}
        stats['Object'] = self.type
        stats['MD5'] = hashlib.md5(self.value).hexdigest()
        stats['SHA1'] = hashlib.sha1(self.value).hexdigest()
        if self.isCompressed():
            stats['Compressed in'] = str(self.compressedIn)
        else:
            stats['Compressed in'] = None
        stats['References'] = str(self.references)
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        if self.dictType != '':
            stats['Type'] = self.dictType
        else:
            stats['Type'] = None
        if self.elements.has_key('/Subtype'):
            stats['Subtype'] = self.elements['/Subtype'].getValue()
        else:
            stats['Subtype'] = None
        if self.elements.has_key('/S'):
            stats['Action type'] = self.elements['/S'].getValue()
        else:
            stats['Action type'] = None
        if self.containsJScode:
            stats['JSCode'] = True
            if len(self.unescapedBytes) > 0:
                stats['Escaped Bytes'] = True
            else:
                stats['Escaped Bytes'] = False
            if len(self.urlsFound) > 0:
                stats['URLs'] = True
            else:
                stats['URLs'] = False
        else:
            stats['JSCode'] = False
        return stats
            
    def getUnescapedBytes(self):
        '''
            Gets the escaped bytes of the object unescaped 
            
            @return: An array of unescaped bytes (string)
        '''
        return self.unescapedBytes
    
    def getURLs(self):
        '''
            Gets the URLs of the object 
            
            @return: An array of URLs
        '''
        return self.urlsFound
        
    def hasElement(self, name):
        '''
            Specifies if the dictionary contains the element with the given name
            
            @param name: The element
            @return: A boolean
        '''
        if self.elements.has_key(name):
            return True
        else:
            return False
    
    def replace(self, string1, string2):
        newElements = {}
        stringFound = False
        errorMessage = ''
        for key in self.elements:
            if key.find(string1) != -1:
                newKey = key.replace(string1, string2)
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            else:
                newKey = key
            newObject = self.elements[key]
            if newObject != None:
                ret = newObject.replace(string1, string2)
                if ret[0] == -1:
                    if ret[1] != 'String not found' or not stringFound:
                        errorMessage = ret[1]
                else:
                    stringFound = True
                    if errorMessage == 'String not found':
                        errorMessage = ''
                newElements[newKey] = newObject
        if not stringFound:
            return (-1,'String not found')
        self.elements = newElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret

    def setElement(self, name, value, update = True):
        '''
            Sets the element with the given name to the given value. If it does not exist a new element is created.
            
            @param name: The element to add or modify
            @param value: The new value of the element 
            @param update: A boolean indicating if it's necessary an update of the object. By default: True.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.elements[name] = value
        if update:
            ret = self.update()
            return ret
        return (0,'')

    def setElements(self, newElements):
        '''
            Sets the dictionary of elements
            
            @param newElements: The new dictionary of elements
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.elements = newElements
        ret = self.update()
        return ret

    def setElementValue(self, name, value, update = True):
        '''
            Sets the value of the element with the given name.
            
            @param name: The element to modify
            @param value: The new value of the element 
            @param update: A boolean indicating if it's necessary an update of the object. By default: True.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        if self.elements.has_key(name):
            self.elements[name].setValue(value)
            if update:
                ret = self.update()
                return ret
            return (0,'')
        else:
            return (-1,'Element not found')


class PDFStream (PDFDictionary) :
    '''
        Stream object of a PDF document
    '''
    def __init__(self, rawDict = '', rawStream = '', elements = {}, rawNames = {}) :
        global isForceMode
        self.type = 'stream'
        self.dictType = ''
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.decodedStream = ''
        self.encodedStream = ''
        self.encryptedValue = rawDict
        self.rawValue = rawDict
        self.rawNames = rawNames
        self.elements = elements
        self.value = ''
        self.updateNeeded = False
        self.containsJScode = False
        self.rawStream = rawStream
        self.encryptedStream = rawStream
        self.xrefStream = False
        self.newFilters = False
        self.deletedFilters = False
        self.modifiedStream = False
        self.modifiedRawStream = True
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.referencesInElements = {}
        self.references = []
        self.size = 0
        self.filter = None
        self.filterParams = None
        self.file = None
        self.isEncodedStream = False
        self.decodingError = False
        if elements == {}:
            errorMessage = 'No dictionary in stream object'
            if isForceMode:
                self.addError(errorMessage)
            else:
                raise Exception(errorMessage)
        ret = self.update()
        if ret[0] == -1:
            if isForceMode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])

    def update(self, onlyElements = False, decrypt = False, algorithm = 'RC4'):
        '''
            Updates the object after some modification has occurred
            
            @param onlyElements: A boolean indicating if it's only necessary to update the stream dictionary or also the stream itself. By default: False (stream included).
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.value = '<< '
        self.rawValue = '<< '
        self.encryptedValue = '<< '
        keys = self.elements.keys()
        values = self.elements.values()
        if not onlyElements:
            self.references = []
            self.errors = []
            self.JSCode = []
            self.unescapedBytes = []
            self.urlsFound = []
            self.containsJScode = False
            self.decodingError = False
            
        # Dictionary
        if self.elements.has_key('/Type') and self.elements['/Type'] != None:
            if self.elements['/Type'].getValue() == '/XRef':
                self.xrefStream = True
        if self.elements.has_key('/Length'):
            length = self.elements['/Length']
            if length != None:
                if length.getType() == 'integer':
                    self.size = length.getRawValue()
                elif length.getType() == 'reference':
                    self.updateNeeded = True
                    self.referencesInElements['/Length'] = [length.getId(),'']
                else:
                    if isForceMode:
                        self.addError('No permitted type for /Length element')
                    else:
                        return (-1,'No permitted type for /Length element')
            else:
                if isForceMode:
                    self.addError('None /Length element')
                else:
                    return (-1,'None /Length element')
        else:
            if isForceMode:
                self.addError('Missing /Length in stream object')
            else:
                return (-1,'Missing /Length in stream object')
            
        if self.elements.has_key('/F'):
            self.file = self.elements['/F'].getValue()
            if os.path.exists(self.file):
                self.rawStream = open(self.file,'rb').read()
            else:
                if isForceMode:
                    self.addError('File "'+self.file+'" does not exist (/F)')
                    self.rawStream = ''
                else:
                    return (-1,'File "'+self.file+'" does not exist (/F)')
            
        if self.elements.has_key('/Filter'):
            self.filter = self.elements['/Filter']
            if self.newFilters or self.modifiedStream:
                self.encodedStream = ''
                self.rawStream = ''
            elif not self.encrypted:
                self.encodedStream = self.rawStream
            self.isEncodedStream = True
        elif self.elements.has_key('/FFilter'):
            self.filter = self.elements['/FFilter']
            if self.newFilters or self.modifiedStream:
                self.encodedStream = ''
                self.rawStream = ''
            elif not self.encrypted:
                self.encodedStream = self.rawStream
            self.isEncodedStream = True
        else:
            self.encodedStream = ''
            if self.deletedFilters or self.modifiedStream:
                self.rawStream = self.decodedStream
            elif not self.encrypted:
                self.decodedStream = self.rawStream
            self.isEncodedStream = False
        if self.isEncodedStream:
            if self.elements.has_key('/DecodeParms'):
                self.filterParams = self.elements['/DecodeParms']
            elif self.elements.has_key('/FDecodeParms'):
                self.filterParams = self.elements['/FDecodeParms']
            elif self.elements.has_key('/DP'):
                self.filterParams = self.elements['/DP']
            else:
                self.filterParams = None
                
        for i in range(len(keys)):
            valueElement = values[i]
            if valueElement == None:
                errorMessage = 'Stream dictionary has a None value'
                self.addError(errorMessage)
                valueElement = PDFString('')
            v = valueElement.getValue()
            type = valueElement.getType()
            if type == 'reference':
                if v not in self.references: 
                    self.references.append(v)
            elif type == 'dictionary' or type == 'array':
                self.references = list(set(self.references + valueElement.getReferences()))
            if valueElement.containsJS():
                self.containsJScode = True
                self.JSCode = list(set(self.JSCode + valueElement.getJSCode()))
                self.unescapedBytes = list(set(self.unescapedBytes + valueElement.getUnescapedBytes()))
                self.urlsFound = list(set(self.urlsFound + valueElement.getURLs()))
            if valueElement.isFaulty():
                for error in valueObject.getErrors():
                    self.addError('Children element contains errors: ' + error)
            if self.rawNames.has_key(keys[i]):
                rawName = self.rawNames[keys[i]]
                rawValue = rawName.getRawValue()
            else:
                rawValue = keys[i]
                self.rawNames[keys[i]] = PDFName(keys[i][1:])
            if type in ['string','hexstring','array','dictionary'] and self.encrypted and not decrypt:
                ret = valueElement.encrypt(self.encryptionKey)
                if ret[0] == -1:
                    errorMessage = ret[1]+' in child element'
                    self.addError(errorMessage)
            self.encryptedValue += rawValue + ' ' + str(valueElement.getEncryptedValue()) + newLine
            self.rawValue += rawValue + ' ' + str(valueElement.getRawValue()) + newLine
            self.value += keys[i] + ' ' + v + newLine
        self.encryptedValue = self.encryptedValue[:-1] + ' >>'
        self.rawValue = self.rawValue[:-1] + ' >>'
        self.value = self.value[:-1] + ' >>'
        
        if not onlyElements:
            # Stream
            if self.deletedFilters or self.newFilters or self.modifiedStream or self.modifiedRawStream or self.encrypted:
                if self.deletedFilters:
                    if self.encrypted:
                        try:
                            self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                        except:
                            errorMessage = 'Error encrypting stream with RC4'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1,errorMessage)
                        self.size = len(self.rawStream)
                    else:
                        self.size = len(self.decodedStream)
                elif self.newFilters:
                    ret = self.encode()
                    if ret[0] != -1:
                        if self.encrypted:
                            try:
                                self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                            except:
                                errorMessage = 'Error encrypting stream with RC4'
                                if isForceMode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.size = len(self.rawStream)
                        else:
                            self.size = len(self.encodedStream)
                elif self.modifiedStream:
                    refs = re.findall('(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                    if refs != []:
                        self.references += refs
                        self.references = list(set(self.references))
                    if isJavascript(self.decodedStream):
                        self.containsJScode = True
                        self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], isManualAnalysis)
                        if jsErrors != []:
                            for jsError in jsErrors:
                                errorMessage = 'Error analysing Javascript: '+jsError
                                if isForceMode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                    if self.isEncodedStream:
                        ret = self.encode()
                        if ret[0] != -1:
                            if self.encrypted:
                                try:
                                    self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                                except:
                                    errorMessage = 'Error encrypting stream with RC4'
                                    if isForceMode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                                self.size = len(self.rawStream)
                            else:
                                self.size = len(self.encodedStream)
                    else:
                        if self.encrypted:
                            try:
                                self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                            except:
                                errorMessage = 'Error encrypting stream with RC4'
                                if isForceMode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.size = len(self.rawStream)
                        else:
                            self.size = len(self.decodedStream)
                elif self.modifiedRawStream:
                    if len(self.encodedStream) > 0 or len(self.decodedStream) > 0:
                        self.cleanStream()
                    if not self.updateNeeded:
                        if self.encrypted:
                            if self.isEncodedStream:
                                if decrypt:
                                    try:
                                        if algorithm == 'RC4':
                                            self.encodedStream = RC4(self.encodedStream,self.encryptionKey)
                                        elif algorithm == 'AES':
                                            ret = AES.decryptData(self.encodedStream,self.encryptionKey)
                                            if ret[0] != -1:
                                                self.encodedStream = ret[1]
                                            else:
                                                errorMessage = 'AES decryption error: '+ret[1]
                                                if isForceMode:
                                                    self.addError(errorMessage)
                                                else:
                                                    return (-1,errorMessage)
                                    except:
                                        errorMessage = 'Error decrypting stream with '+str(algorithm)
                                        if isForceMode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                                else:
                                    self.encodedStream = self.rawStream
                                    try:
                                        self.rawStream = RC4(self.rawStream,self.encryptionKey)
                                    except:
                                        errorMessage = 'Error encrypting stream with RC4'
                                        if isForceMode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                                self.decode()
                            else:
                                if not decrypt:
                                    self.decodedStream = self.rawStream                                
                                try:
                                    rc4Result = RC4(self.rawStream,self.encryptionKey)
                                    if decrypt:
                                        self.decodedStream = rc4Result
                                    else:
                                        self.rawStream = rc4Result
                                except:
                                    errorMessage = 'Error encrypting stream with RC4'
                                    if isForceMode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                        else:
                            if self.isEncodedStream:
                                self.decode()
                        self.size = len(self.rawStream)
                        if not self.isFaultyDecoding():
                            refs = re.findall('(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                            if refs != []:
                                self.references += refs
                                self.references = list(set(self.references))
                            if isJavascript(self.decodedStream):
                                self.containsJScode = True
                                self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], isManualAnalysis)
                                if jsErrors != []:
                                    for jsError in jsErrors:
                                        errorMessage = 'Error analysing Javascript: '+jsError
                                        if isForceMode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                else:
                    if not decrypt:
                        try:
                            if self.isEncodedStream:
                                self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                            else:
                                self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                        except:
                            errorMessage = 'Error encrypting stream with RC4'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1,errorMessage)
                        self.size = len(self.rawStream)
                    else:
                        if self.isEncodedStream:
                            try:
                                if algorithm == 'RC4':
                                    self.encodedStream = RC4(self.encodedStream,self.encryptionKey)
                                elif algorithm == 'AES':
                                    ret = AES.decryptData(self.encodedStream,self.encryptionKey)
                                    if ret[0] != -1:
                                        self.encodedStream = ret[1]
                                    else:
                                        errorMessage = 'AES decryption error: '+ret[1]
                                        if isForceMode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                            except:
                                errorMessage = 'Error decrypting stream with '+str(algorithm)
                                if isForceMode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.decode()
                        else:
                            try:
                                if algorithm == 'RC4':
                                    self.decodedStream = RC4(self.decodedStream,self.encryptionKey)
                                elif algorithm == 'AES':
                                    ret = AES.decryptData(self.decodedStream,self.encryptionKey)
                                    if ret[0] != -1:
                                        self.decodedStream = ret[1]
                                    else:
                                        errorMessage = 'AES decryption error: '+ret[1]
                                        if isForceMode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                            except:
                                errorMessage = 'Error decrypting stream with '+str(algorithm)
                                if isForceMode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                        if not self.isFaultyDecoding():
                            refs = re.findall('(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                            if refs != []:
                                self.references += refs
                                self.references = list(set(self.references))
                            if isJavascript(self.decodedStream):
                                self.containsJScode = True
                                self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], isManualAnalysis)
                                if jsErrors != []:
                                    for jsError in jsErrors:
                                        errorMessage = 'Error analysing Javascript: '+jsError
                                        if isForceMode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                if not self.modifiedRawStream:
                    self.modifiedStream = False
                    self.newFilters = False
                    self.deletedFilters = False
                    errors = self.errors
                    try:
                        self.setElement('/Length',PDFNum(str(self.size)))
                        self.errors += errors
                    except:
                        errorMessage = 'Error creating PDFNum'
                        if isForceMode:
                            self.addError(errorMessage)
                        else:
                            return (-1,errorMessage)
                else:
                    self.modifiedRawStream = False
                    self.modifiedStream = False
                    self.newFilters = False
                    self.deletedFilters = False
        if self.errors != []:
            return (-1,self.errors[-1])
        else:
            return (0,'')

    def cleanStream(self):
        '''
            Cleans the start and end of the stream
        '''
        if self.isEncodedStream:
            stream = self.encodedStream
            tmpStream = self.encodedStream
        else:
            stream = self.decodedStream
            tmpStream = self.decodedStream
        '''
        garbage = len(stream) - self.size
        if garbage > 0:
            for i in range(len(tmpStream)):
                if garbage == 0:
                    break
                if tmpStream[i] == '\r' or tmpStream[i] == '\n':
                    stream = stream[1:]
                    garbage -= 1
                else:
                    break
            for i in range(len(tmpStream)-1,0,-1):
                if garbage == 0:
                    break
                if tmpStream[i] == '\r' or tmpStream[i] == '\n':
                    stream = stream[:-1]
                    garbage -= 1
                else:
                    break
        '''
        streamLength = len(stream)
        '''
        if streamLength > 1 and stream[:2] == '\r\n':
            stream = stream[2:]
            streamLength -= 2
        elif streamLength > 0 and (stream[0] == '\r' or stream[0] == '\n'):
            stream = stream[1:]
            streamLength -= 1
        '''
        if streamLength > 1 and stream[-2:] == '\r\n':
            stream = stream[:-2]
        elif streamLength > 0 and (stream[-1] == '\r' or stream[-1] == '\n'):
            stream = stream[:-1]
        if self.isEncodedStream:
            self.encodedStream = stream
        else:
            self.decodedStream = stream

    def contains(self, string):
        value = str(self.value)
        rawValue = str(self.rawValue)
        encValue = str(self.encryptedValue)
        rawStream = str(self.rawStream)
        encStream = str(self.encodedStream)
        decStream = str(self.decodedStream)
        if re.findall(string,value,re.IGNORECASE) != [] or re.findall(string,rawValue,re.IGNORECASE) != [] or re.findall(string,encValue,re.IGNORECASE) != [] or re.findall(string,rawStream,re.IGNORECASE) != [] or re.findall(string,encStream,re.IGNORECASE) != [] or re.findall(string,decStream,re.IGNORECASE) != []:
            return True
        if self.containsJS():
            for js in self.JSCode:
                if re.findall(string,js,re.IGNORECASE) != []:
                    return True
        return False        
    
    def decode (self) :
        '''
            Decodes the stream and stores the result in decodedStream 
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        errorMessage = ''
        if len(self.rawStream) > 0:
            if self.isEncodedStream:
                if self.filter == None:
                    errorMessage = 'Bad /Filter element'
                    self.addError(errorMessage)
                    return (-1,errorMessage)
                filterType = self.filter.getType()
                if self.filterParams != None:
                    filterParamsType = self.filterParams.getType()
                if filterType == 'name':
                    if self.filterParams == None:
                        ret = decodeStream(self.encodedStream, self.filter.getValue(), self.filterParams)
                        if ret[0] == -1:
                            if self.rawStream != self.encodedStream:
                                ret = decodeStream(self.rawStream, self.filter.getValue(), self.filterParams)
                            if ret[0] == -1:
                                self.decodingError = True
                                errorMessage = 'Decoding error: '+ret[1]
                                if isForceMode:
                                    self.addError(errorMessage)
                                    self.decodedStream = ''
                                else:
                                    return (-1,errorMessage)
                            else:
                                self.decodedStream = ret[1]
                        else:
                            self.decodedStream = ret[1]
                    elif filterParamsType == 'dictionary':
                        ret = decodeStream(self.encodedStream, self.filter.getValue(), self.filterParams.getElements())            
                        if ret[0] == -1:
                            if self.rawStream != self.encodedStream:
                                ret = decodeStream(self.rawStream, self.filter.getValue(), self.filterParams.getElements())
                            if ret[0] == -1:
                                self.decodingError = True
                                errorMessage = 'Decoding error: '+ret[1]
                                if isForceMode:
                                    self.addError(errorMessage)
                                    self.decodedStream = ''
                                else:
                                    return (-1,errorMessage)
                            else:
                                self.decodedStream = ret[1]
                        else:
                            self.decodedStream = ret[1]
                    else:
                        if isForceMode:
                            errorMessage = 'Filter parameters type is not valid'
                            self.addError(errorMessage)
                            self.decodedStream = ''
                        else:
                            return (-1,'Filter parameters type is not valid')
                elif filterType == 'array':
                    self.decodedStream = self.encodedStream
                    filterElements = self.filter.getElements()
                    for i in range(len(filterElements)):
                        filter = filterElements[i]
                        if filter == None:
                            if isForceMode:
                                errorMessage = 'Bad /Filter element in PDFArray'
                                self.addError(errorMessage)
                                continue
                            return (-1,'Bad /Filter element in PDFArray')
                        if filter.getType() == 'name':
                            if self.filterParams == None:
                                ret = decodeStream(self.decodedStream, filter.getValue(), self.filterParams)
                                if ret[0] == -1:
                                    if i == 0 and self.rawStream != self.encodedStream:
                                        ret = decodeStream(self.rawStream, filter.getValue(), self.filterParams)
                                    if ret[0] == -1:
                                        self.decodingError = True
                                        errorMessage = 'Decoding error: '+ret[1]
                                        if isForceMode:
                                            self.addError(errorMessage)
                                            self.decodedStream = ''
                                        else:
                                            return (-1,errorMessage)
                                    else:
                                        self.decodedStream = ret[1]
                                else:
                                    self.decodedStream = ret[1]
                            elif filterParamsType == 'array':
                                paramsArray = self.filterParams.getElements()
                                if i >= len(paramsArray):
                                    paramsObj = None
                                    paramsDict = {}
                                else:
                                    paramsObj = paramsArray[i]
                                    if paramsObj == None:
                                        if isForceMode:
                                            errorMessage = 'Bad /FilterParms element in PDFArray'
                                            self.addError(errorMessage)
                                            continue
                                        return (-1,'Bad /FilterParms element in PDFArray')
                                    paramsObjType = paramsObj.getType()
                                    if paramsObjType == 'dictionary':
                                        paramsDict = paramsObj.getElements()
                                    else:
                                        paramsDict = {}
                                ret = decodeStream(self.decodedStream, filter.getValue(), paramsDict)
                                if ret[0] == -1:
                                    if i == 0 and self.rawStream != self.encodedStream:
                                        ret = decodeStream(self.rawStream, filter.getValue(), paramsDict)
                                    if ret[0] == -1:
                                        self.decodingError = True
                                        errorMessage = 'Decoding error: '+ret[1]
                                        if isForceMode:
                                            self.addError(errorMessage)
                                            self.decodedStream = ''
                                        else:
                                            return (-1,errorMessage)
                                    else:
                                        self.decodedStream = ret[1]
                                else:
                                    self.decodedStream = ret[1]
                            else:
                                if isForceMode:
                                    errorMessage = 'One of the filters parameters type is not valid'
                                    self.addError(errorMessage)
                                    self.decodedStream = ''
                                else:
                                    return (-1,'One of the filters parameters type is not valid')
                        else:
                            if isForceMode:
                                errorMessage = 'One of the filters type is not valid'
                                self.addError(errorMessage)
                                self.decodedStream = ''
                            else:
                                return (-1,'One of the filters type is not valid')
                else:
                    if isForceMode:
                        errorMessage = 'Filter type is not valid'
                        self.addError(errorMessage)
                        self.decodedStream = ''
                    else:
                        return (-1,'Filter type is not valid')
                if errorMessage != '':
                    return (-1,errorMessage)
                else:
                    return (0,'')
            else:
                return (-1,'Not encoded stream')
        else:
            return (-1,'Empty stream')            

    def decrypt(self, password = None, strAlgorithm = 'RC4', altAlgorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        errorMessage = ''
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        decryptedElements = {}
        for key in self.elements:
            object = self.elements[key]
            objectType = object.getType()
            if objectType in ['string','hexstring','array','dictionary']:
                ret = object.decrypt(self.encryptionKey, strAlgorithm)
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(ret[1])
            decryptedElements[key] = object
        self.elements = decryptedElements
        ret = self.update(decrypt = True, algorithm = altAlgorithm)
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
    
    def delElement(self, name, update = True):
        onlyElements = True
        if self.elements.has_key(name):
            if name in ['/Filter','/DecodeParm','/FFilter','/FDecodeParm']:
                self.deletedFilters = True
                onlyElements = False
            del(self.elements[name])
            if update:
                ret = self.update(onlyElements = onlyElements)
            return ret
        else:
            return (-1,'Element not found')

    def encode (self) :
        '''
            Encode the decoded stream and update the content of rawStream
        '''
        errorMessage = ''
        if len(self.decodedStream) > 0:
            if self.filter == None:
                return (-1,'Bad /Filter element')
            filterType = self.filter.getType()
            if self.filterParams != None:
                filterParamsType = self.filterParams.getType()
            if filterType == 'name':
                if self.filterParams == None:
                    ret = encodeStream(self.decodedStream, self.filter.getValue(), self.filterParams)
                    if ret[0] == -1:
                        errorMessage = 'Encoding error: '+ret[1]
                        if isForceMode:
                            self.addError(errorMessage)
                            self.encodedStream = ''
                        else:
                            return (-1,errorMessage)
                    else:
                        self.rawStream = ret[1]
                elif filterParamsType == 'dictionary':
                    ret = encodeStream(self.decodedStream, self.filter.getValue(), self.filterParams.getElements())
                    if ret[0] == -1:
                        errorMessage = 'Encoding error: '+ret[1]
                        if isForceMode:
                            self.addError(errorMessage)
                            self.encodedStream = ''
                        else:
                            return (-1,errorMessage)
                    else:
                        self.rawStream = ret[1]        
                else:
                    if isForceMode:
                        errorMessage = 'Filter parameters type is not valid'
                        self.addError(errorMessage)
                        self.encodedStream = ''
                    else:
                        return (-1,'Filter parameters type is not valid')
            elif filterType == 'array':
                self.rawStream = self.decodedStream
                filterElements = list(self.filter.getElements())
                filterElements.reverse()
                if self.filterParams != None and filterParamsType == 'array':
                    paramsArray = self.filterParams.getElements()
                    for j in range(len(paramsArray),len(filterElements)):
                        paramsArray.append(PDFNull('Null'))
                    paramsArray.reverse()
                else:
                    paramsArray = []
                for i in range(len(filterElements)):
                    filter = filterElements[i]
                    if filter == None:
                        if isForceMode:
                            errorMessage = 'Bad /Filter element in PDFArray'
                            self.addError(errorMessage)
                            continue
                        return (-1,'Bad /Filter element in PDFArray')
                    if filter.getType() == 'name':
                        if self.filterParams == None:
                            ret = encodeStream(self.rawStream, filter.getValue(), self.filterParams)
                            if ret[0] == -1:
                                errorMessage = 'Encoding error: '+ret[1]
                                if isForceMode:
                                    self.addError(errorMessage)
                                    self.encodedStream = ''
                                else:
                                    return (-1,errorMessage)
                            else:
                                self.rawStream = ret[1]
                        elif filterParamsType == 'array':
                            paramsObj = paramsArray[i]
                            if paramsObj == None:
                                if isForceMode:
                                    errorMessage = 'Bad /FilterParms element in PDFArray'
                                    self.addError(errorMessage)
                                    continue
                                return (-1,'Bad /FilterParms element in PDFArray')
                            paramsObjType = paramsObj.getType()
                            if paramsObjType == 'dictionary':
                                paramsDict = paramsObj.getElements()
                            else:
                                paramsDict = {}

                            ret = encodeStream(self.rawStream, filter.getValue(), paramsDict)
                            if ret[0] == -1:
                                errorMessage = 'Encoding error: '+ret[1]
                                if isForceMode:
                                    self.addError(errorMessage)
                                    self.encodedStream = ''
                                else:
                                    return (-1,errorMessage)
                            else:
                                self.rawStream = ret[1]    
                        else:
                            if isForceMode:
                                errorMessage = 'One of the filters parameters type is not valid'
                                self.addError(errorMessage)
                                self.encodedStream = ''
                            else:
                                return (-1,'One of the filters parameters type is not valid')
                    else:
                        if isForceMode:
                            errorMessage = 'One of the filters type is not valid'
                            self.addError(errorMessage)
                            self.encodedStream = ''
                        else:
                            return (-1,'One of the filters type is not valid')
            else:
                if isForceMode:
                    errorMessage = 'Filter type is not valid'
                    self.addError(errorMessage)
                    self.encodedStream = ''
                else:
                    return (-1,'Filter type is not valid')
            self.encodedStream = self.rawStream
            if errorMessage != '':
                return (-1,errorMessage)
            else:
                return (0,'')
        else:
            return (-1,'Empty stream')
    
    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        ret = self.update()
        return ret
                    
    def getEncryptedValue(self):
        return self.encryptedValue + newLine + 'stream' + newLine + self.rawStream + newLine + 'endstream'

    def getStats(self):
        stats = {}
        stats['Object'] = self.type
        stats['MD5'] = hashlib.md5(self.value).hexdigest()
        stats['SHA1'] = hashlib.sha1(self.value).hexdigest()
        stats['Stream MD5'] = hashlib.md5(self.decodedStream).hexdigest()
        stats['Stream SHA1'] = hashlib.sha1(self.decodedStream).hexdigest()
        stats['Raw Stream MD5'] = hashlib.md5(self.rawStream).hexdigest()
        stats['Raw Stream SHA1'] = hashlib.sha1(self.rawStream).hexdigest()
        if self.isCompressed():
            stats['Compressed in'] = str(self.compressedIn)
        else:
            stats['Compressed in'] = None
        stats['References'] = str(self.references)
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        if self.dictType != '':
            stats['Type'] = self.dictType
        else:
            stats['Type'] = None
        if self.elements.has_key('/Subtype'):
            stats['Subtype'] = self.elements['/Subtype'].getValue()
        else:
            stats['Subtype'] = None
        if self.elements.has_key('/S'):
            stats['Action type'] = self.elements['/S'].getValue()
        else:
            stats['Action type'] = None
        stats['Length'] = str(self.size)
        if self.size != len(self.rawStream):
            stats['Real Length'] = str(len(self.rawStream))
        else:
            stats['Real Length'] = None
        if self.isEncodedStream:
            stats['Encoded'] = True
            if self.file != None:
                stats['Stream File'] = self.file
            else:
                stats['Stream File'] = None
            stats['Filters'] = self.filter.getValue()
            if self.filterParams != None:
                stats['Filter Parameters'] = True
            else:
                stats['Filter Parameters'] = False
            if self.decodingError:
                stats['Decoding Errors'] = True
            else:
                stats['Decoding Errors'] = False
        else:
            stats['Encoded'] = False
        if self.containsJScode:
            stats['JSCode'] = True
            if len(self.unescapedBytes) > 0:
                stats['Escaped Bytes'] = True
            else:
                stats['Escaped Bytes'] = False
            if len(self.urlsFound) > 0:
                stats['URLs'] = True
            else:
                stats['URLs'] = False
        else:
            stats['JSCode'] = False
        return stats
    
    def getStream(self):
        '''
            Gets the stream of the object 
            
            @return: The stream of the object (string), this means applying filters or decoding characters
        '''
        return self.decodedStream
    
    def getRawStream(self):
        '''
            Gets the raw value of the stream of the object 
            
            @return: The raw value of the stream (string), this means without applying filters or decoding characters
        '''
        return self.rawStream

    def getRawValue(self):
        if self.isEncoded():
            stream = self.encodedStream
        else:
            stream = self.decodedStream
        return self.rawValue + newLine + 'stream' + newLine + stream + newLine + 'endstream'
    
    def getValue(self):
        return self.value + newLine +'stream' + newLine + self.decodedStream + newLine + 'endstream'
    
    def isEncoded(self):
        '''
            Specifies if the stream is encoded with some type of filter (/Filter) 
            
            @return: A boolean
        '''
        return self.isEncodedStream
    
    def isFaultyDecoding(self):
        '''
            Specifies if there are any errors in the process of decoding the stream 
            
            @return: A boolean
        '''
        return self.decodingError
    
    def replace(self, string1, string2):
        stringFound = False
        # Dictionary
        newElements = {}
        errorMessage = ''
        for key in self.elements:
            if key == '/F' and self.elements[key] != None:
                externalFile = self.elements[key].getValue()
                if externalFile != self.file:
                    self.modifiedRawStream = True
                    self.decodedStream = ''
            if key.find(string1) != -1:
                newKey = key.replace(string1, string2)
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            else:
                newKey = key
            newObject = self.elements[key]
            ret = newObject.replace(string1, string2)
            if ret[0] == -1:
                if ret[1] != 'String not found' or not stringFound:
                    errorMessage = ret[1]
            else:
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            newElements[newKey] = newObject
        # Stream
        if not self.modifiedRawStream:
            oldDecodedStream = self.decodedStream
            if self.decodedStream.find(string1) != -1:
                self.decodedStream = self.decodedStream.replace(string1,string2)
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            if oldDecodedStream != self.decodedStream:
                self.modifiedStream = True
        if not stringFound:
            return (-1,'String not found')
        self.elements = newElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret

    def resolveReferences(self):
        errorMessage = ''
        if self.referencesInElements.has_key('/Length'):
            value = self.referencesInElements['/Length'][1]
            self.size = int(value)
            self.cleanStream()
        self.updateNeeded = False
        ret = self.decode()
        if ret[0] == -1:
            errorMessage = ret[1]
        refs = re.findall('(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
        if refs != []:
            self.references += refs
            self.references = list(set(self.references))
        if isJavascript(self.decodedStream):
            self.containsJScode = True
            self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], isManualAnalysis)
            if jsErrors != []:
                for jsError in jsErrors:
                    errorMessage = 'Error analysing Javascript: '+jsError
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,'')

    def setDecodedStream(self, newStream):
        '''
            Sets the decoded value of the stream and updates the object if some modification is needed
            
            @param newStream: The new raw value (string)
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.decodedStream = newStream
        self.modifiedStream = True
        ret = self.update()
        return ret
    
    def setElement(self, name, value, update = True):
        onlyElements = True
        if name in ['/Filter','/DecodeParm','/FFilter','/FDecodeParm']:
            self.newFilters = True
            onlyElements = False
        self.elements[name] = value
        if update:
            ret = self.update(onlyElements = onlyElements)
            return ret
        return (0,'')
    
    def setElements(self, newElements):
        diffElements = []
        oldElements = self.elements.keys()
        for oldElement in oldElements:
            if oldElement not in newElements:
                if oldElement in ['/Filter','/FFilter']:
                    self.deletedFilters = True
                    onlyElements = False
                    break
        self.elements = newElements
        if not self.deletedFilters:
            for name in self.elements:
                if name in ['/Filter','/DecodeParm','/FFilter','/FDecodeParm']:
                    self.newFilters = True
                    onlyElements = False
                    break
        ret = self.update()
        return ret

    def setRawStream(self, newStream):
        '''
            Sets the raw value of the stream and updates the object if some modification is needed
            
            @param newStream: The new raw value (string)
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.rawStream = newStream
        self.modifiedRawStream = True
        ret = self.update()
        return ret
    

class PDFObjectStream (PDFStream) :
    def __init__(self, rawDict = '', rawStream = '', elements = {}, rawNames = {}, compressedObjectsDict = {}) :
        global isForceMode
        self.type = 'stream'
        self.dictType = ''
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.decodedStream = ''
        self.encodedStream = ''
        self.rawStream = rawStream
        self.newRawStream = False
        self.newFilters = False
        self.deletedFilters = False
        self.modifiedStream = False
        self.modifiedRawStream = True
        self.rawValue = rawDict
        self.encryptedValue = rawDict
        self.rawNames = rawNames
        self.value = '' # string
        self.updateNeeded = False
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.referencesInElements = {}
        self.references = []
        self.elements = elements
        self.compressedObjectsDict = compressedObjectsDict
        self.indexes = []
        self.firstObjectOffset = 0
        self.numCompressedObjects = 0
        self.extends = None
        self.size = 0
        self.filter = None
        self.filterParams = None
        self.file = None
        self.isEncodedStream = False
        self.decodingError = False
        if elements != {}:
            ret = self.update()
            if ret[0] == -1:
                if isForceMode:
                    self.addError(ret[1])
                else:
                    raise Exception(ret[1]) 
        else:
            self.addError('No dictionary in stream object')

    def update(self, modifiedCompressedObjects = False, onlyElements = False, decrypt = False, algorithm = 'RC4'):
        '''
            Updates the object after some modification has occurred
            
            @param modifiedCompressedObjects: A boolean indicating if the compressed objects hav been modified. By default: False.
            @param onlyElements: A boolean indicating if it's only necessary to update the stream dictionary or also the stream itself. By default: False (stream included).
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.value = '<< '
        self.rawValue = '<< '
        self.encryptedValue = '<< '
        keys = self.elements.keys()
        values = self.elements.values()
        if not onlyElements:
            self.errors = []
            self.references = []
            self.JSCode = []
            self.unescapedBytes = []
            self.urlsFound = []
            self.containsJScode = False
            self.decodingError = False
            
        # Dictionary
        if self.elements.has_key('/First') and self.elements['/First'] != None:
            self.firstObjectOffset = self.elements['/First'].getRawValue()
        else:
            if isForceMode:
                self.addError('No /First element in the object stream or it\'s None')
            else:
                return (-1,'No /First element in the object stream or it\'s None')
        if self.elements.has_key('/N') and self.elements['/N'] != None:
            self.numCompressedObjects = self.elements['/N'].getRawValue()
        else:
            if isForceMode:
                self.addError('No /N element in the object stream or it\'s None')
            else:
                return (-1,'No /N element in the object stream or it\'s None')

        if self.elements.has_key('/Extends') and self.elements['/Extends'] != None:
            self.extends = self.elements['/Extends'].getValue()

        if self.elements.has_key('/Length'):
            length = self.elements['/Length']
            if length != None:
                if length.getType() == 'integer':
                    self.size = length.getRawValue()
                elif length.getType() == 'reference':
                    self.updateNeeded = True
                    self.referencesInElements['/Length'] = [length.getId(),'']
                else:
                    if isForceMode:
                        self.addError('No permitted type for /Length element')
                    else:
                        return (-1,'No permitted type for /Length element')
            else:
                if isForceMode:
                    self.addError('None /Length element')
                else:
                    return (-1,'None /Length element')
        else:
            if isForceMode:
                self.addError('Missing /Length in stream object')
            else:
                return (-1,'Missing /Length in stream object')
            
        if self.elements.has_key('/F'):
            self.file = self.elements['/F'].getValue()
            if os.path.exists(self.file):
                self.rawStream = open(self.file,'rb').read()
            else:
                if isForceMode:
                    self.addError('File "'+self.file+'" does not exist (/F)')
                    self.rawStream = ''
                else:
                    return (-1,'File "'+self.file+'" does not exist (/F)')            
            
        if self.elements.has_key('/Filter'):
            self.filter = self.elements['/Filter']
            if self.newFilters or self.modifiedStream:
                self.encodedStream = ''
                self.rawStream = ''
            elif not self.encrypted:
                self.encodedStream = self.rawStream
            self.isEncodedStream = True
        elif self.elements.has_key('/FFilter'):
            self.filter = self.elements['/FFilter']
            if self.newFilters or self.modifiedStream:
                self.encodedStream = ''
                self.rawStream = ''
            elif not self.encrypted:
                self.encodedStream = self.rawStream
            self.isEncodedStream = True
        else:
            self.encodedStream = ''
            if self.deletedFilters or self.modifiedStream:
                self.rawStream = self.decodedStream
            elif not self.encrypted:
                self.decodedStream = self.rawStream
            self.isEncodedStream = False
        if self.isEncodedStream:
            if self.elements.has_key('/DecodeParms'):
                self.filterParams = self.elements['/DecodeParms']
            elif self.elements.has_key('/FDecodeParms'):
                self.filterParams = self.elements['/FDecodeParms']
            elif self.elements.has_key('/DP'):
                self.filterParams = self.elements['/DP']
            else:
                self.filterParams = None
                
        for i in range(len(keys)):
            valueElement = values[i]
            if valueElement == None:
                if isForceMode:
                    errorMessage = 'Stream dictionary has a None value'
                    self.addError(errorMessage)
                    valueElement = PDFString('')
                else:
                    return (-1,'Stream dictionary has a None value')
            v = valueElement.getValue()
            type = valueElement.getType()
            if type == 'reference':
                if v not in self.references: 
                    self.references.append(v)
            elif type == 'dictionary' or type == 'array':
                self.references = list(set(self.references + valueElement.getReferences()))
            if valueElement.containsJS():
                self.containsJScode = True
                self.JSCode = list(set(self.JSCode + valueElement.getJSCode()))
                self.unescapedBytes = list(set(self.unescapedBytes + valueElement.getUnescapedBytes()))
                self.urlsFound = list(set(self.urlsFound + valueElement.getURLs()))
            if valueElement.isFaulty():
                errorMessage = 'Child element is faulty'
                self.addError(errorMessage)
            if self.rawNames.has_key(keys[i]):
                rawName = self.rawNames[keys[i]]
                rawValue = rawName.getRawValue()
            else:
                rawValue = keys[i]
                self.rawNames[keys[i]] = PDFName(keys[i][1:])
            if type in ['string','hexstring','array','dictionary'] and self.encrypted and not decrypt:
                ret = valueElement.encrypt(self.encryptionKey)
                if ret[0] == -1:
                    errorMessage = ret[1]+' in child element'
                    self.addError(errorMessage)
            self.encryptedValue += rawValue + ' ' + str(valueElement.getEncryptedValue()) + newLine
            self.rawValue += rawValue + ' ' + str(valueElement.getRawValue()) + newLine
            self.value += keys[i] + ' ' + v + newLine
        self.encryptedValue = self.encryptedValue[:-1] + ' >>'
        self.rawValue = self.rawValue[:-1] + ' >>'
        self.value = self.value[:-1] + ' >>'
        
        if not onlyElements:
            # Stream
            if self.deletedFilters or self.newFilters or self.modifiedStream or self.modifiedRawStream or modifiedCompressedObjects or self.encrypted:
                if self.deletedFilters:
                    if self.encrypted:
                        try:
                            self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                        except:
                            errorMessage = 'Error encrypting stream with RC4'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1,errorMessage)
                        self.size = len(self.rawStream)
                    else:
                        self.size = len(self.decodedStream)
                elif self.newFilters:
                    ret = self.encode()
                    if ret[0] != -1:
                        if self.encrypted:
                            try:
                                self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                            except:
                                errorMessage = 'Error encrypting stream with RC4'
                                if isForceMode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.size = len(self.rawStream)
                        else:
                            self.size = len(self.encodedStream)
                else:
                    if self.modifiedStream or self.modifiedRawStream:
                        if self.modifiedStream:
                            if self.isEncodedStream:
                                ret = self.encode()
                                if ret[0] != -1:
                                    if self.encrypted:
                                        try:
                                            self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                                        except:
                                            errorMessage = 'Error encrypting stream with RC4'
                                            if isForceMode:
                                                self.addError(errorMessage)
                                            else:
                                                return (-1,errorMessage)
                                        self.size = len(self.rawStream)
                                    else:
                                        self.size = len(self.encodedStream)
                            else:
                                if self.encrypted:
                                    try:
                                        self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                                    except:
                                        errorMessage = 'Error encrypting stream with RC4'
                                        if isForceMode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                                    self.size = len(self.rawStream)
                                else:
                                    self.size = len(self.decodedStream)
                        elif self.modifiedRawStream:
                            if len(self.rawStream) > 0:
                                self.cleanStream()
                            if not self.updateNeeded:
                                if self.encrypted:
                                    if self.isEncodedStream:
                                        if decrypt:
                                            try:
                                                if algorithm == 'RC4':
                                                    self.encodedStream = RC4(self.rawStream,self.encryptionKey)
                                                elif algorithm == 'AES':
                                                    ret = AES.decryptData(self.rawStream,self.encryptionKey)
                                                    if ret[0] != -1:
                                                        self.encodedStream = ret[1]
                                                    else:
                                                        errorMessage = 'AES decryption error: '+ret[1]
                                                        if isForceMode:
                                                            self.addError(errorMessage)
                                                        else:
                                                            return (-1,errorMessage)
                                            except:
                                                errorMessage = 'Error decrypting stream with '+str(algorithm)
                                                if isForceMode:
                                                    self.addError(errorMessage)
                                                else:
                                                    return (-1,errorMessage)
                                        else:
                                            self.encodedStream = self.rawStream
                                            try:
                                                self.rawStream = RC4(self.rawStream,self.encryptionKey)
                                            except:
                                                errorMessage = 'Error encrypting stream with RC4'
                                                if isForceMode:
                                                    self.addError(errorMessage)
                                                else:
                                                    return (-1,errorMessage)
                                        self.decode()
                                    else:
                                        try:
                                            self.decodedStream = RC4(self.rawStream,self.encryptionKey)
                                        except:
                                            errorMessage = 'Error encrypting stream with RC4'
                                            if isForceMode:
                                                self.addError(errorMessage)
                                            else:
                                                return (-1,errorMessage)
                                else:
                                    if self.isEncodedStream:
                                        self.decode()
                                self.size = len(self.rawStream)
                        offsetsSection = self.decodedStream[:self.firstObjectOffset]
                        objectsSection = self.decodedStream[self.firstObjectOffset:]
                        numbers = re.findall('\d{1,10}', offsetsSection)
                        if numbers != [] and len(numbers) % 2 == 0:
                            for i in range(0,len(numbers),2):
                                id = int(numbers[i])
                                offset = int(numbers[i+1])
                                ret = PDFParser().readObject(objectsSection[offset:])
                                if ret[0] == -1:
                                    if isForceMode:
                                        object = None
                                        self.addError(ret[1])
                                    else:
                                        return ret
                                else:
                                    object = ret[1]
                                self.compressedObjectsDict[id] = [offset,object]
                                self.indexes.append(id)
                        else:
                            if isForceMode:
                                self.addError('Missing offsets in object stream')
                            else:
                                return (-1,'Missing offsets in object stream')
                    elif modifiedCompressedObjects:
                        tmpStreamObjects = ''
                        tmpStreamObjectsInfo = ''
                        for objectId in self.indexes:
                            offset = len(tmpStreamObjects)
                            tmpStreamObjectsInfo += str(objectId)+' '+str(offset)+' '
                            object = self.compressedObjectsDict[objectId][1]
                            tmpStreamObjects += object.toFile()
                            self.compressedObjectsDict[objectId] = [offset,object]
                        self.decodedStream = tmpStreamObjectsInfo + tmpStreamObjects
                        self.firstObjectOffset = len(tmpStreamObjectsInfo)
                        self.setElementValue('/First',str(self.firstObjectOffset))
                        self.numCompressedObjects = len(self.compressedObjectsDict)
                        self.setElementValue('/N',str(self.numCompressedObjects))
                        if self.isEncodedStream:
                            self.encode()
                            self.size = len(self.encodedStream)
                        else:
                            self.size = len(self.decodedStream)
                    else:
                        if not decrypt:
                            try:
                                if self.isEncodedStream:
                                    self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                                else:
                                    self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                            except:
                                errorMessage = 'Error encrypting stream with RC4'
                                if isForceMode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.size = len(self.rawStream)
                        else:
                            if self.isEncodedStream:
                                try:
                                    if algorithm == 'RC4':
                                        self.encodedStream = RC4(self.rawStream,self.encryptionKey)
                                    elif algorithm == 'AES':
                                        ret = AES.decryptData(self.rawStream,self.encryptionKey)
                                        if ret[0] != -1:
                                            self.encodedStream = ret[1]
                                        else:
                                            errorMessage = 'AES decryption error: '+ret[1]
                                            if isForceMode:
                                                self.addError(errorMessage)
                                            else:
                                                return (-1,errorMessage)
                                except:
                                    errorMessage = 'Error decrypting stream with '+str(algorithm)                    
                                    if isForceMode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                                self.decode()
                            else:
                                try:
                                    if algorithm == 'RC4':
                                        self.decodedStream = RC4(self.rawStream,self.encryptionKey)
                                    elif algorithm == 'AES':
                                        ret = AES.decryptData(self.rawStream,self.encryptionKey)
                                        if ret[0] != -1:
                                            self.decodedStream = ret[1]
                                        else:
                                            errorMessage = 'AES decryption error: '+ret[1]
                                            if isForceMode:
                                                self.addError(errorMessage)
                                            else:
                                                return (-1,errorMessage)
                                except:
                                    errorMessage = 'Error decrypting stream with '+str(algorithm)                                
                                    if isForceMode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                            offsetsSection = self.decodedStream[:self.firstObjectOffset]
                            objectsSection = self.decodedStream[self.firstObjectOffset:]
                            numbers = re.findall('\d{1,10}', offsetsSection)
                            if numbers != [] and len(numbers) % 2 == 0:
                                for i in range(0,len(numbers),2):
                                    id = int(numbers[i])
                                    offset = int(numbers[i+1])
                                    ret = PDFParser().readObject(objectsSection[offset:])
                                    if ret[0] == -1:
                                        if isForceMode:
                                            object = None
                                            self.addError(ret[1])
                                        else:
                                            return ret
                                    else:
                                        object = ret[1]
                                    self.compressedObjectsDict[id] = [offset,object]
                                    self.indexes.append(id)
                            else:
                                if isForceMode:
                                    self.addError('Missing offsets in object stream')
                                else:
                                    return (-1,'Missing offsets in object stream')
                    if not self.isFaultyDecoding():
                        refs = re.findall('(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                        if refs != []:
                            self.references += refs
                            self.references = list(set(self.references))
                        if isJavascript(self.decodedStream):
                            self.containsJScode = True
                            self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], isManualAnalysis)
                            if jsErrors != []:
                                for jsError in jsErrors:
                                    errorMessage = 'Error analysing Javascript: '+jsError
                                    if isForceMode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                if not self.modifiedRawStream:
                    self.modifiedStream = False
                    self.newFilters = False
                    self.deletedFilters = False
                    errors = self.errors
                    try:
                        self.setElement('/Length',PDFNum(str(self.size)))
                        self.errors += errors
                    except:
                        errorMessage = 'Error creating PDFNum'
                        if isForceMode:
                            self.addError(errorMessage)
                        else:
                            return (-1,errorMessage)
                else:
                    self.modifiedRawStream = False
                    self.modifiedStream = False
                    self.newFilters = False
                    self.deletedFilters = False
        if self.errors != []:
            return (-1,self.errors[-1])
        else:
            return (0,'')

    def getCompressedObjects(self):
        '''
            Gets the information of the compressed objects: offset and content. 
            
            @return: A dictionary with this information: {id: [offset,PDFObject]}
        '''
        return self.compressedObjectsDict

    def getObjectIndex(self, id):
        '''
            Gets the index of the object in the dictionary of compressed objects 
            
            @param id: The object id
            @return: The index (int) or None if the object hasn't been found
        '''
        if id not in self.indexes:
            return None
        else:
            return self.indexes.index(id)
                    
    def replace(self, string1, string2):
        stringFound = False
        # Dictionary
        newElements = {}
        errorMessage = ''
        for key in self.elements:
            if key == '/F' and self.elements[key] != None:
                externalFile = self.elements[key].getValue()
                if externalFile != self.file:
                    self.modifiedRawStream = True
                    self.decodedStream = ''
            if key.find(string1) != -1:
                newKey = key.replace(string1, string2)
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            else:
                newKey = key
            newObject = self.elements[key]
            ret = newObject.replace(string1, string2)
            if ret[0] == -1:
                if ret[1] != 'String not found' or not stringFound:
                    errorMessage = ret[1]
            else:
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            newElements[newKey] = newObject
        # Stream
        if not self.modifiedRawStream:
            if self.decodedStream.find(string1) != -1:
                modifiedObjects = True
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            for compressedObjectId in self.compressedObjectsDict:
                object = self.compressedObjectsDict[compressedObjectId][1]
                object.replace(string1,string2)
                self.compressedObjectsDict[compressedObjectId][1] = object
        if not stringFound:
            return (-1,'String not found')
        self.elements = newElements
        ret = self.update(modifiedObjects)
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
                    
    def resolveReferences(self):
        errorMessage = ''
        if self.referencesInElements.has_key('/Length'):
            value = self.referencesInElements['/Length'][1]
            self.size = int(value)
            self.cleanStream()
        self.updateNeeded = False
        if self.isEncodedStream:
            ret = self.decode()
            if ret[0] == -1:
                return ret
            if not self.isFaultyDecoding():
                refs = re.findall('(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                if refs != []:
                    self.references += refs
                    self.references = list(set(self.references))
                # Extracting the compressed objects
                offsetsSection = self.decodedStream[:self.firstObjectOffset]
                objectsSection = self.decodedStream[self.firstObjectOffset:]
                numbers = re.findall('\d{1,10}', offsetsSection)
                if numbers != [] and len(numbers) % 2 == 0:
                    for i in range(0,len(numbers),2):
                        id = numbers[i]
                        offset = numbers[i+1]
                        ret = PDFParser.readObject(objectsSection[offset:])
                        if ret[0] == -1:
                            if isForceMode:
                                object = None
                                self.addError(ret[1])
                            else:
                                return ret
                        else:
                            object = ret[1]
                        self.compressedObjectsDict[numbers[i]] = [offset,object]
                else:
                    errorMessage = 'Missing offsets in object stream'
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
        if errorMessage != '':
            return (-1,errorMessage)
        else:
            return (0,'')
    
    def setCompressedObjectId(self,id):
        '''
            Sets the compressedIn attribute of the compressed object defined by its id
            
            @param id: The object id
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        for compressedId in self.compressedObjectsDict:
            if self.compressedObjectsDict[compressedId] != None:
                object = self.compressedObjectsDict[compressedId][1]
                object.setCompressedIn(id)
                self.compressedObjectsDict[compressedId][1] = object
            else:
                return (-1,'Compressed object corrupted')
        return (0,'')


class PDFIndirectObject :
    def __init__(self) :
        self.referenced = [] # int[]
        self.object = None # PDFObject
        self.offset = 0 # int
        self.generationNumber = 0 # int
        self.id = None # int
        self.size = 0 # int
        
    def contains(self, string):
        return self.object.contains(string)

    def getErrors(self):
        return self.object.getErrors()
    
    def getGenerationNumber(self):
        return self.generationNumber
    
    def getId(self):
        return self.id
    
    def getObject(self):
        return self.object

    def getOffset(self):
        return self.offset
        
    def getReferences(self):
        return self.object.getReferences()
    
    def getSize(self):
        return self.size

    def getStats(self):
        stats = self.object.getStats()
        if self.offset != -1:
            stats['Offset'] = str(self.offset)
        else:
            stats['Offset'] = None
        stats['Size'] = str(self.size)
        return stats

    def isFaulty(self):
        return self.object.isFaulty()
    
    def setGenerationNumber(self, generationNumber):
        self.generationNumber = generationNumber
        
    def setId(self, id):
        self.id = id
    
    def setObject(self, object):
        self.object = object
    
    def setOffset(self, offset):
        self.offset = offset

    def setSize(self, newSize):
        self.size = newSize    

    def toFile(self):
        rawValue = self.object.toFile()
        output = str(self.id)+' '+str(self.generationNumber)+' obj' + newLine + rawValue + newLine + 'endobj' + newLine*2
        self.size = len(output)
        return output


class PDFCrossRefSection :
    def __init__(self) :
        self.errors = []
        self.streamObject = None
        self.offset = 0
        self.size = 0
        self.subsections = [] # PDFCrossRefSubsection []
        self.bytesPerField = []

    def addEntry(self, objectId, newEntry):
        prevSubsection = 0
        errorMessage = ''
        for i in range(len(self.subsections)):
            subsection = self.subsections[i]
            ret = subsection.addEntry(newEntry, objectId)
            if ret[0] != -1:
                break
            else:
                errorMessage = ret[1]
                self.addError(errorMessage)
            if subsection.getFirstObject() + subsection.getNumObjects() < objectId:
                prevSubsection = i
        else:
            try:
                newSubsection = PDFCrossRefSubSection(objectId, 1, [newEntry])
            except:
                errorMessage = 'Error creating new PDFCrossRefSubSection'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
            self.subsections.insert(prevSubsection, newSubsection)
        if errorMessage != '':
            return (-1,errorMessage)
        else:
            return (0,'')
        
    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def addSubsection(self, subsection):
        self.subsections.append(subsection)
    
    def delEntry(self, objectId):
        prevSubsection = 0
        errorMessage = ''
        for i in range(len(self.subsections)):
            subsection = self.subsections[i]
            numEntry = subsection.getIndex(objectId)
            if numEntry != None:
                if subsection.getNumObjects() == 1:
                    self.subsections.remove(subsection)
                else:
                    ret = subsection.delEntry(objectId)
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(ret[1])
                        continue
        if errorMessage != '':
            return (-1,errorMessage)
        else:
            return (0,'')
    
    def getBytesPerField(self):
        return self.bytesPerField

    def getErrors(self):
        return self.errors

    def getFreeObjectIds(self):
        ids = []
        for subsection in self.subsections:
            ids += subsection.getFreeObjectIds()
        return ids
    
    def getNewObjectIds(self):
        ids = []
        for subsection in self.subsections:
            ids += subsection.getNewObjectIds()
        return ids
    
    def getOffset(self):
        return self.offset
    
    def getSize(self):
        return self.size
    
    def getStats(self):
        stats = {}
        if self.offset != -1:
            stats['Offset'] = str(self.offset)
        else:
            stats['Offset'] = None
        stats['Size'] = str(self.size)
        if self.inStream():
            stats['Stream'] = str(self.streamObject)
        else:
            stats['Stream'] = None
        stats['Subsections'] = []
        for i in range(len(self.subsections)):
            subsection = self.subsections[i]
            subStats = {}
            subStats['Entries'] = str(len(subsection.getEntries()))
            if subsection.isFaulty():
                subStats['Errors'] = str(len(subsection.getErrors()))
            else:
                subStats['Errors'] = None
            stats['Subsections'].append(subStats)
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        return stats

    def getSubsectionsArray(self):
        return self.subsections

    def getSubsectionsNumber(self):
        return len(self.subsections)

    def getXrefStreamObject(self):
        return self.streamObject

    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True
        
    def inStream(self):
        if self.streamObject != None:
            return True
        else:
            return False
        
    def setBytesPerField(self, array):
        self.bytesPerField = array        

    def setOffset(self, offset):
        self.offset = offset
                
    def setSize(self, newSize):
        self.size = newSize

    def setXrefStreamObject(self, id):
        self.streamObject = id

    def toFile(self):
        output = 'xref' + newLine
        for subsection in self.subsections:
            output += subsection.toFile()
        return output

    def updateOffset(self, objectId, newOffset):
        for subsection in self.subsections:
            updatedEntry = subsection.getEntry(objectId)
            if updatedEntry != None: 
                updatedEntry.setObjectOffset(newOffset)
                ret = subsection.setEntry(objectId, updatedEntry)
                if ret[0] == -1:
                    self.addError(errorMessage)
                return ret
        else:
            errorMessage = 'Object entry not found'
            self.addError(errorMessage)
            return (-1,errorMessage)


class PDFCrossRefSubSection:
    def __init__(self, firstObject, numObjects = 0, newEntries = [], offset = 0) :
        self.errors = []
        self.offset = offset
        self.size = 0
        self.firstObject = int(firstObject)
        self.numObjects = int(numObjects)
        self.entries = newEntries

    def addEntry(self, newEntry, objectId = None):
        if objectId == None:
            self.entries.append(newEntry)
            self.numObjects += 1
            return (0,self.numObjects)
        else:
            numEntry = self.getIndex(objectId)
            if numEntry != None:
                self.entries.insert(numEntry, newEntry)
                self.numObjects += 1
                return (0,self.numObjects)
            else:
                if self.firstObject == objectId + 1:
                    self.entries.insert(0, newEntry)
                    self.firstObject = objectId
                    self.numObjects += 1
                    return (0,self.numObjects)
                elif objectId == self.firstObject + self.numObjects:
                    self.entries.append(newEntry)
                    self.numObjects += 1
                    return (0,self.numObjects)
                else:
                    errorMessage = 'Unspecified error'
                    self.addError(errorMessage)
                    return (-1,errorMessage)
                return (0,self.numObjects)
    
    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def delEntry(self, objectId):
        numEntry = self.getIndex(objectId)
        if numEntry == None:
            errorMessage = 'Entry not found'
            self.addError(errorMessage)
            return (-1,errorMessage)
        if numEntry == 0:
            self.entries.pop(numEntry)
            self.firstObject = objectId + 1
            self.numObjects -= 1
        elif numEntry == self.numObjects - 1:
            self.entries.pop(numEntry)
            self.numObjects -= 1
        else:
            entry = self.entries[numEntry]
            numPrevFree = self.getPrevFree(numEntry)
            numNextFree = self.getNextFree(numEntry)
            nextObject = self.getObjectId(numNextFree)
            if numPrevFree != None:
                prevEntry = self.entries[numPrevFree]
                prevEntry.setNextObject(objectId)
                self.entries[numPrevFree] = prevEntry
            entry.setType('f')
            if nextObject == None:
                entry.setNextObject(0)
            else:
                entry.setNextObject(nextObject)
            entry.incGenNumber()
            self.entries[numEntry] = entry
        return (0,numEntry)    

    def getEntries(self):
        return self.entries
        
    def getEntry(self, objectId):
        numEntry = self.getIndex(objectId)
        if numEntry != None:
            return self.entries[numEntry]
        else:
            return None
        
    def getErrors(self):
        return self.errors

    def getFirstObject(self):
        return self.firstObject

    def getFreeObjectIds(self):
        ids = []
        for i in range(len(self.entries)):
            if self.entries[i].getType() == 'f':
                ids.append(self.getObjectId(i))
        return ids    
    
    def getIndex(self, objectId):
        objectIds = range(self.firstObject,self.firstObject+self.numObjects)
        if objectId in objectIds:
            return objectIds.index(objectId)
        else:
            return None

    def getNextFree(self, numEntry):
        for i in range(numEntry + 1,self.numObjects):
            if self.entries[i].getType() == 'f':
                return i
        else:
            return None
        
    def getNewObjectIds(self):
        ids = []
        for i in range(len(self.entries)):
            if self.entries[i].getType() == 'n':
                ids.append(self.getObjectId(i))
        return ids

    def getNumObjects(self):
        return self.numObjects

    def getObjectId(self, numEntry):
        return self.firstObject + numEntry
            
    
    def getOffset(self):
        return self.offset
    
        
    def getPrevFree(self, numEntry):
        for i in range(numEntry):
            if self.entries[i].getType() == 'f':
                return i
        else:
            return None

    def getSize(self):
        return self.size
    
    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True
        
    def setEntry(self, objectId, newEntry):
        numEntry = self.getIndex(objectId)
        if numEntry != None:
            self.entries[numEntry] = newEntry
            return (0,numEntry)
        else:
            errorMessage = 'Entry not found'
            self.addError(errorMessage)
            return (-1,errorMessage)
        
    def setEntries(self, newEntries):
        self.entries = newEntries

    def setFirstObject(self, newFirst):
        self.firstObject = newFirst
        
    def setNumObjects(self, newNumObjects):
        self.numObjects = newNumObjects

    def setOffset(self, offset):
        self.offset = offset
        
    def setSize(self, newSize):
        self.size = newSize
    
    def toFile(self):
        output = str(self.firstObject) + ' ' + str(self.numObjects) + newLine
        for entry in self.entries:
            output += entry.toFile()
        return output
            

class PDFCrossRefEntry:
    def __init__(self, firstValue, secondValue, type, offset = 0) :
        self.errors = []
        self.offset = offset
        self.objectStream = None
        self.indexObject = None
        self.genNumber = None
        self.objectOffset = None
        self.nextObject = None
        self.entryType = type
        if type == 'f' or type == 0:
            self.nextObject = int(firstValue)
            self.genNumber = int(secondValue)            
        elif type == 'n' or type == 1:
            self.objectOffset = int(firstValue)
            self.genNumber = int(secondValue)            
        elif type == 2:
            self.objectStream = int(firstValue)
            self.indexObject = int(secondValue)
        else:
            if isForceMode:
                self.addError('Error parsing xref entry')
            else:
                return (-1,'Error parsing xref entry')

    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def getEntryBytes(self, bytesPerField):
        bytesString = ''
        errorMessage = ''
            
        if self.entryType == 'f' or self.entryType == 0:
            type = 0
            firstValue = self.nextObject
            secondValue = self.genNumber
        elif self.entryType == 'n' or self.entryType == 1:
            type = 1
            firstValue = self.objectOffset
            secondValue = self.genNumber
        else:
            type = 2
            firstValue = self.objectStream
            secondValue = self.indexObject

        if bytesPerField[0] != 0:
            ret = numToHex(type,bytesPerField[0])
            if ret[0] == -1:
                errorMessage = ret[1]
                if isForceMode:
                    self.addError(ret[1])
                    ret = numToHex(0,bytesPerField[0])
                    bytesString += ret[1]
                else:
                    return ret
            else:
                bytesString += ret[1]
        if bytesPerField[1] != 0:
            ret = numToHex(firstValue,bytesPerField[1])
            if ret[0] == -1:
                errorMessage = ret[1]
                if isForceMode:
                    self.addError(ret[1])
                    ret = numToHex(0,bytesPerField[1])
                    bytesString += ret[1]
                else:
                    return ret
            else:
                bytesString += ret[1]
        if bytesPerField[2] != 0:
            ret = numToHex(secondValue,bytesPerField[2])
            if ret[0] == -1:
                errorMessage = ret[1]
                if isForceMode:
                    self.addError(ret[1])
                    ret = numToHex(0,bytesPerField[1])
                    bytesString += ret[1]
                else:
                    return ret
            else:
                bytesString += ret[1]
        if errorMessage != '':
            return (-1,errorMessage)    
        return (0,bytesString) 
    
    def getErrors(self):
        return self.errors
    
    def getGenNumber(self):
        return self.genNumber

    def getIndexObject(self):
        return self.indexObject
    
    def getNextObject(self):
        return self.nextObject

    def getObjectOffset(self):
        return self.objectOffset

    def getObjectStream(self):
        return self.objectStream
            
    def getOffset(self):
        return self.offset

    def getType(self):
        return self.entryType
    
    def incGenNumber(self):
        self.genNumber += 1
        
    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True
        
    def setGenNumber(self, newGenNumber):
        self.genNumber = newGenNumber
        
    def setIndexObject(self, index):
        self.indexObject = index

    def setNextObject(self, newNextObject):
        self.nextObject = newNextObject

    def setObjectOffset(self, newOffset):
        self.objectOffset = newOffset
                    
    def setObjectStream(self, id):
        self.objectStream = id
        
    def setOffset(self, offset):
        self.offset = offset

    def setType(self, newType):
        self.entryType = newType
        
            
    def toFile(self):
        output = ''
        if self.entryType == 'n':
            ret = numToString(self.objectOffset,10)
            if ret[0] != -1:
                output += ret[1]
        elif self.entryType == 'f':
            ret = numToString(self.nextObject,10)
            if ret[0] != -1:
                output += ret[1]
        output += ' '
        ret = numToString(self.genNumber, 5)
        if ret[0] != -1:
            output += ret[1]
        output += ' '
        output += self.entryType
        if len(newLine) == 2:
            output += newLine
        else:
            output += ' ' + newLine
        return output


class PDFBody :
    def __init__(self) :
        self.numObjects = 0 # int
        self.objects = {} # PDFIndirectObjects{}
        self.numStreams = 0 # int
        self.numEncodedStreams = 0
        self.numDecodingErrors = 0
        self.streams = []
        self.nextOffset = 0
        self.encodedStreams = []
        self.faultyStreams = []
        self.faultyObjects = []
        self.containingJS = []
        self.suspiciousEvents = {}
        self.suspiciousActions = {}
        self.suspiciousElements = {}
        self.vulns = {}
        self.JSCode = []
        self.URLs = []
        self.toUpdate = []
        self.xrefStreams = []
        self.objectStreams = []
        self.compressedObjects = []
        self.errors = []

    def addCompressedObject(self, id):
        if id not in self.compressedObjects:
            self.compressedObjects.append(id)

    def addObjectStream(self, id):
        if id not in self.objectStreams:
            self.objectStreams.append(id)

    def addXrefStream(self, id):
        if id not in self.xrefStreams:
            self.xrefStreams.append(id)

    def containsCompressedObjects(self):
        if len(self.compressedObjects) > 0:
            return True
        else:
            return False

    def containsObjectStreams(self):
        if len(self.objectStreams) > 0:
            return True
        else:
            return False

    def containsXrefStreams(self):
        if len(self.xrefStreams) > 0:
            return True
        else:
            return False
            
    def delObject(self, id):
        if self.objects.has_key(id):
            indirectObject = self.objects[id]
            return self.deregisterObject(indirectObject)
        else:
            return None

    def deregisterObject(self, pdfIndirectObject):
        type = ''
        errorMessage = ''
        if pdfIndirectObject == None:
            errorMessage = 'Indirect Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        id = pdfIndirectObject.getId()
        if self.objects.has_key(id):
            self.objects.pop(id)
        pdfObject = pdfIndirectObject.getObject()
        if pdfObject == None:
            errorMessage = 'Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        objectType = pdfObject.getType()
        self.numObjects -= 1
        if id in self.faultyObjects:
            self.faultyObjects.remove(id)
        self.updateStats(id,pdfObject,delete=True)
        if not pdfObject.updateNeeded:
            if objectType == 'stream':
                self.numStreams -= 1
                if id in self.streams:
                    self.streams.remove(id)
                if pdfObject.isEncoded():
                    if id in self.encodedStreams:
                        self.encodedStreams.remove(id)
                    self.numEncodedStreams -= 1
                    if id in self.faultyStreams:
                        self.faultyStreams.remove(id)
                        self.numDecodingErrors -= 1
                if pdfObject.hasElement('/Type'):
                    typeObject = pdfObject.getElementByName('/Type')
                    if typeObject == None:
                        errorMessage = '/Type element is None'
                        if isForceMode:
                            pdfFile.addError(errorMessage)
                        else:
                            return (-1,errorMessage)
                    else:
                        type = typeObject.getValue()
                        if type == '/XRef':
                            if id in self.xrefStreams:
                                self.xrefStreams.remove(id)
                        elif type == '/ObjStm':
                            if id in self.objectStreams:
                                self.objectStreams.remove(id)
                            compressedObjectsDict = pdfObject.getCompressedObjects()
                            for compressedId in compressedObjectsDict:
                                if compressedId in self.compressedObjects:
                                    self.compressedObjects.remove(compressedId)
                                self.delObject(compressedId)
                            del(compressedObjectsDict)
        objectErrors = pdfObject.getErrors()
        if objectErrors != []:
            index = 0
            errorsAux = list(self.errors)
            while True:
                if objectErrors[0] not in errorsAux:
                    break
                indexAux = errorsAux.index(objectErrors[0])
                if errorsAux[indexAux:indexAux+len(objectErrors)] == objectErrors:
                    for i in range(len(objectErrors)):
                        self.errors.pop(index+indexAux)
                    break
                else:
                    errorsAux = errorsAux[indexAux+len(objectErrors):]
                    index = indexAux+len(objectErrors)
        if type == '':
            type = objectType
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,type)

    def encodeChars(self):
        errorMessage = ''
        for id in self.objects:
            indirectObject = self.objects[id]
            if indirectObject != None:
                object = indirectObject.getObject()
                if object != None:
                    objectType = object.getType()
                    if objectType in ['string','name','array','dictionary','stream']: 
                        ret = object.encodeChars()
                        if ret[0] == -1:
                            errorMessage = ret[1]
                            pdfFile.addError(errorMessage)
                        indirectObject.setObject(object)
                        self.deregisterObject(indirectObject)
                        self.registerObject(indirectObject)
                else:
                    errorMessage = 'Bad object found while encoding strings'
                    pdfFile.addError(errorMessage)
            else:
                errorMessage = 'Bad indirect object found while encoding strings'
                pdfFile.addError(errorMessage)
        if errorMessage != '':
            return (-1,typeObject)
        return (0,'')

    def getCompressedObjects(self):
        return self.compressedObjects
    
    def getContainingJS(self):
        return self.containingJS

    def getEncodedStreams(self):
        return self.encodedStreams
    
    def getFaultyObjects(self):
        return self.faultyObjects
    
    def getFaultyStreams(self):
        return self.faultyStreams
        
    def getIndirectObject(self, id):
        if self.objects.has_key(id):
            return self.objects[id]
        else:
            return None

    def getJSCode(self):
        return self.JSCode
    
    def getNextOffset(self):
        return self.nextOffset

    def getNumDecodingErrors(self):
        return self.numDecodingErrors
        
    def getNumEncodedStreams(self):
        return self.numEncodedStreams
    
    def getNumFaultyObjects(self):
        return len(self.faultyObjects)

    def getNumObjects(self):
        return self.numObjects
    
    def getNumStreams(self):
        return self.numStreams

    def getObject(self, id, indirect = False):
        if self.objects.has_key(id):
            indirectObject = self.objects[id]
            if indirect:
                return indirectObject
            else:
                return indirectObject.getObject()
        else:
            return None

    def getObjects(self):
        return self.objects    

    def getObjectsByString (self, toSearch) :
        matchedObjects = []
        for indirectObject in self.objects.values():
            if indirectObject.contains(toSearch):
                matchedObjects.append(indirectObject.getId())
        return matchedObjects
    
    def getObjectsIds(self):
        sortedIdsOffsets = []
        sortedIds = []
        for indirectObject in self.objects.values():
            sortedIdsOffsets.append([indirectObject.getId(),indirectObject.getOffset()])
        sortedIdsOffsets = sorted(sortedIdsOffsets, key=lambda x: x[1])
        for i in range(len(sortedIdsOffsets)):
            sortedIds.append(sortedIdsOffsets[i][0])
        return sortedIds

    def getObjectStreams(self):
        return self.objectStreams
    
    def getStreams(self):
        return self.streams

    def getSuspiciousActions(self):
        return self.suspiciousActions
    
    def getSuspiciousElements(self):
        return self.suspiciousElements
    
    def getSuspiciousEvents(self):
        return self.suspiciousEvents
    
    def getURLs(self):
        return self.URLs

    def getVulns(self):
        return self.vulns
        
    def getXrefStreams(self):
        return self.xrefStreams

    def registerObject(self, pdfIndirectObject):
        type = ''
        errorMessage = ''
        if pdfIndirectObject == None:
            errorMessage = 'Indirect Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        id = pdfIndirectObject.getId()
        pdfObject = pdfIndirectObject.getObject()
        if pdfObject == None:
            errorMessage = 'Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        objectType = pdfObject.getType()
        self.numObjects += 1
        if pdfObject.isFaulty():
            self.faultyObjects.append(id)
        ret = self.updateStats(id,pdfObject)
        if ret[0] == -1:
            errorMessage = ret[1]
        if pdfObject.updateNeeded:
            self.toUpdate.append(id)
        else:
            if objectType == 'stream':
                self.numStreams += 1
                self.streams.append(id)
                if pdfObject.isEncoded():
                    self.encodedStreams.append(id)
                    self.numEncodedStreams += 1
                    if pdfObject.isFaultyDecoding():
                        self.faultyStreams.append(id)
                        self.numDecodingErrors += 1
                if pdfObject.hasElement('/Type'):
                    typeObject = pdfObject.getElementByName('/Type')
                    if typeObject == None:
                        errorMessage = '/Type element is None'
                        if isForceMode:
                            pdfFile.addError(errorMessage)
                        else:
                            return (-1,errorMessage)
                    else: 
                        type = typeObject.getValue()
                        if type == '/XRef':
                            self.addXrefStream(id)
                        elif type == '/ObjStm':
                            self.addObjectStream(id)
                            pdfObject.setCompressedObjectId(id)
                            compressedObjectsDict = pdfObject.getCompressedObjects()
                            for compressedId in compressedObjectsDict:
                                self.addCompressedObject(compressedId)
                                offset = compressedObjectsDict[compressedId][0]
                                compressedObject = compressedObjectsDict[compressedId][1]
                                self.setObject(compressedId, compressedObject, offset)
                            del(compressedObjectsDict)
        pdfIndirectObject.setObject(pdfObject)
        self.objects[id] = pdfIndirectObject
        self.errors += pdfObject.getErrors()
        if type == '':
            type = objectType
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,type)    

    def setNextOffset(self, newOffset):
        self.nextOffset = newOffset

    def setObject(self, id = None, object = None, offset = None, modification = False):
        errorMessage = ''
        if self.objects.has_key(id):
            pdfIndirectObject = self.objects[id]
            self.deregisterObject(pdfIndirectObject)
            pdfIndirectObject.setObject(object)
            if offset != None:
                pdfIndirectObject.setOffset(offset)
            size = 12 + 3*len(newLine) + len(str(object.getRawValue())) + len(str(id))
            pdfIndirectObject.setSize(size)
        else:
            if modification:
                errorMessage = 'Object not found'
                if isForceMode:
                    pdfFile.addError(errorMessage)
                else:
                    return (-1,errorMessage)
            if id == None:
                id = self.numObjects+1
            if offset == None:
                offset = self.getNextOffset()
            pdfIndirectObject = PDFIndirectObject()
            pdfIndirectObject.setId(id)
            pdfIndirectObject.setObject(object)
            pdfIndirectObject.setGenerationNumber(0)
            pdfIndirectObject.setOffset(offset)
            size = 12 + 3*len(newLine) + len(str(object.getRawValue())) + len(str(id))
            pdfIndirectObject.setSize(size)
            self.setNextOffset(offset+size)
        ret = self.registerObject(pdfIndirectObject)
        if ret[0] == 0:
            if errorMessage != '':
                return (-1,errorMessage)
            else:
                objectType = ret[1]
                return (0,[id,objectType])
        else:
            return ret


    def setObjects(self, objects):
        self.objects = objects
                
    def updateObjects(self):
        errorMessage = ''
        for id in self.toUpdate:
            updatedElements = {}
            object = self.objects[id].getObject()
            if object == None:
                errorMessage = 'Object is None'
                if isForceMode:
                    pdfFile.addError(errorMessage)
                    continue
                else:
                    return (-1,errorMessage)
            elementsToUpdate = object.getReferencesInElements()
            keys = elementsToUpdate.keys()
            for key in keys:
                ref = elementsToUpdate[key]
                refId = ref[0]
                if refId in self.objects:
                    refObject = self.objects[refId].getObject()
                    if refObject == None:
                        errorMessage = 'Referenced object is None'
                        if isForceMode:
                            pdfFile.addError(errorMessage)
                            continue
                        else:
                            return (-1,errorMessage)
                    ref[1] = refObject.getValue()
                    updatedElements[key] = ref
                else:
                    errorMessage = 'Referenced object not found'
                    if isForceMode:
                        pdfFile.addError(errorMessage)
                        continue
                    else:
                        return (-1,errorMessage)
            object.setReferencesInElements(updatedElements)
            object.resolveReferences()
            if object.getType() == 'stream':
                self.numStreams += 1
                self.streams.append(id)
                if object.isEncoded():
                    self.encodedStreams.append(id)
                    self.numEncodedStreams += 1
                    if object.isFaultyDecoding():
                        self.faultyStreams.append(id)
                        self.numDecodingErrors += 1
                if object.hasElement('/Type'):
                    typeObject = object.getElementByName('/Type')
                    if typeObject == None:
                        errorMessage = 'Referenced element is None'
                        if isForceMode:
                            pdfFile.addError(errorMessage)
                            continue
                        else:
                            return (-1,errorMessage)
                    else: 
                        type = typeObject.getValue()
                        if type == '/XRef':
                            self.addXrefStream(id)
                        elif type == '/ObjStm':
                            self.addObjectStream(id)
                            object.setCompressedObjectId(id)
                            compressedObjectsDict = object.getCompressedObjects()
                            for compressedId in compressedObjectsDict:
                                self.addCompressedObject(compressedId)
                                offset = compressedObjectsDict[compressedId][0]
                                compressedObject = compressedObjectsDict[compressedId][1]
                                self.setObject(compressedId, compressedObject, offset)
                            del(compressedObjectsDict)
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,'')
    
    def updateOffsets (self) :
        pass

    def updateStats(self, id, pdfObject, delete = False):
        if pdfObject == None:
            errorMessage = 'Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        value = pdfObject.getValue()
        for event in monitorizedEvents:
            if value.find(event) != -1:
                printedEvent = event.strip()
                if self.suspiciousEvents.has_key(printedEvent):
                    if delete:
                        if id in self.suspiciousEvents[printedEvent]:
                            self.suspiciousEvents[printedEvent].remove(id)
                    elif id not in self.suspiciousEvents[printedEvent]:
                        self.suspiciousEvents[printedEvent].append(id)
                elif not delete:
                    self.suspiciousEvents[printedEvent] = [id]
        for action in monitorizedActions:
            index = value.find(action)
            if index != -1 and (action == '/JS ' or len(value) == index + len(action) or value[index+len(action)] in delimiterChars+spacesChars):
                printedAction = action.strip()
                if self.suspiciousActions.has_key(printedAction):
                    if delete:
                        if id in self.suspiciousActions[printedAction]:
                            self.suspiciousActions[printedAction].remove(id)
                    elif id not in self.suspiciousActions[printedAction]:
                        self.suspiciousActions[printedAction].append(id)
                elif not delete:
                    self.suspiciousActions[printedAction] = [id]
        for element in monitorizedElements:
            index = value.find(element)
            if index != -1 and (element == '/EmbeddedFiles ' or len(value) == index + len(element) or value[index+len(element)] in delimiterChars+spacesChars):
                printedElement = element.strip()
                if self.suspiciousElements.has_key(printedElement):
                    if delete:
                        if id in self.suspiciousElements[printedElement]:
                            self.suspiciousElements[printedElement].remove(id)
                    elif id not in self.suspiciousElements[printedElement]:
                        self.suspiciousElements[printedElement].append(id)
                elif not delete:
                    self.suspiciousElements[printedElement] = [id]
        if pdfObject.containsJS():
            if delete:
                jsCodeArray = pdfObject.getJSCode()
                if id in self.containingJS:
                    self.containingJS.remove(id)
                    for jsCode in jsCodeArray:
                        if jsCode in self.JSCode:
                            self.JSCode.remove(jsCode)
                        for vuln in jsVulns:
                            if jsCode.find(vuln) != -1:
                                if self.vulns.has_key(vuln) and id in self.vulns[vuln]:
                                    self.vulns[vuln].remove(id)
            else:
                jsCode = pdfObject.getJSCode()
                if id not in self.containingJS:
                    self.containingJS.append(id)
                for js in jsCode:
                    if js not in self.JSCode:
                        self.JSCode.append(js)
                for code in jsCode:
                    for vuln in jsVulns:
                        if code.find(vuln) != -1:
                            if self.vulns.has_key(vuln):
                                self.vulns[vuln].append(id)
                            else:
                                self.vulns[vuln] = [id]
        ## Extra checks
        objectType = pdfObject.getType()
        if objectType == 'stream':
            vulnFound = None
            streamContent = pdfObject.getStream()
            if len(streamContent) > 327 and streamContent[236:240] == 'SING' and streamContent[327] != '\0':
                # CVE-2010-2883
                # http://opensource.adobe.com/svn/opensource/tin/src/SING.cpp
                # http://community.websense.com/blogs/securitylabs/archive/2010/09/10/brief-analysis-on-adobe-reader-sing-table-parsing-vulnerability-cve-2010-2883.aspx
                vulnFound = singUniqueName
            elif streamContent.count('AAL/AAAC/wAAAv8A') > 1000:
                # CVE-2013-2729
                # Adobe Reader BMP/RLE heap corruption
                # http://blog.binamuse.com/2013/05/readerbmprle.html
                vulnFound = bmpVuln
            if vulnFound != None:    
                if self.suspiciousElements.has_key(vulnFound):
                    if delete:
                        if id in self.suspiciousElements[vulnFound]:
                            self.suspiciousElements[vulnFound].remove(id)
                    elif id not in self.suspiciousElements[vulnFound]:
                        self.suspiciousElements[vulnFound].append(id)
                elif not delete:
                    self.suspiciousElements[vulnFound] = [id]
        return (0,'')                        
    


class PDFTrailer :
    def __init__(self, dict, lastCrossRefSection = '0', streamPresent = False):
        self.errors = []
        self.dict = dict
        self.offset = 0
        self.eofOffset = 0
        self.size = 0
        self.streamObject = None
        self.catalogId = None
        self.numObjects = None
        self.id = None
        self.infoId = None
        self.lastCrossRefSection = int(lastCrossRefSection)
        ret = self.update(streamPresent)
        if ret[0] == -1:
            if isForceMode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
        
    def update(self, streamPresent = False):
        errorMessage = ''
        if self.dict == None:
            errorMessage = 'The trailer dictionary is None'
            self.addError(errorMessage)
            return (-1,errorMessage)
        if self.dict.hasElement('/Root'):
            reference = self.dict.getElementByName('/Root')
            if reference != None:
                if reference.getType() == 'reference':
                    self.catalogId = reference.getId()
                else:
                    errorMessage = 'No reference element in /Root'
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
            else:
                errorMessage = 'No reference element in /Root'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        else:
            if not streamPresent:
                errorMessage = 'Missing /Root element'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        if self.dict.hasElement('/Size'):
            size = self.dict.getElementByName('/Size')
            if size != None:
                if size.getType() == 'integer':
                    self.numObjects = size.getRawValue()
                else:
                    errorMessage = 'No integer element in /Size'
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
            else:
                errorMessage = 'No integer element in /Size'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        else:
            if not streamPresent:
                errorMessage = 'Missing /Size element'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        if self.dict.hasElement('/Info'):
            info = self.dict.getElementByName('/Info')
            if info != None:
                if info.getType() == 'reference':
                    self.infoId = info.getId()
                else:
                    errorMessage = 'No reference element in /Info'
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
            else:
                errorMessage = 'No reference element in /Info'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        if self.dict.hasElement('/ID'):
            arrayID = self.dict.getElementByName('/ID')
            if arrayID != None:
                if arrayID.getType() == 'array':
                    self.id = arrayID.getRawValue()    
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,'')

    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)
                
    def encodeChars(self):
        ret = self.dict.encodeChars()
        if ret[0] == -1:
            self.addError(ret[1])
        return ret

    def getCatalogId(self):
        return self.catalogId
    
    def getDictEntry(self, name):
        if self.dict.hasElement(name):
            return self.dict.getElementByName(name)
        else:
            return None

    def getEOFOffset(self):
        return self.eofOffset        

    def getErrors(self):
        return self.errors

    def getID(self):
        return self.id
    
    def getInfoId(self):
        return self.infoId

    def getLastCrossRefSection(self):
        return self.lastCrossRefSection
        
    def getNumObjects(self):
        return self.numObjects
    
    def getOffset(self):
        return self.offset
        
    def getPrevCrossRefSection(self):
        return self.dict.getElementByName('/Prev')
        
    def getSize(self):
        return self.size
        
    def getStats(self):
        stats = {}
        if self.offset != -1:
            stats['Offset'] = str(self.offset)
        else:
            stats['Offset'] = None
        stats['Size'] = str(self.size)
        if self.inStream():
            stats['Stream'] = str(self.streamObject)
        else:
            stats['Stream'] = None
        stats['Objects'] = str(self.numObjects)
        if self.dict.hasElement('/Root'):
            stats['Root Object'] = str(self.catalogId)
        else:
            stats['Root Object'] = None
            self.addError('/Root element not found')
        if self.dict.hasElement('/Info'):
            stats['Info Object'] = str(self.infoId)
        else:
            stats['Info Object'] = None
        if self.dict.hasElement('/ID') and self.id != None and self.id != '' and self.id != ' ':
            stats['ID'] = self.id
        else:
            stats['ID'] = None
        if self.dict.hasElement('/Encrypt'):
            if self.getDictEntry('/Encrypt').getType() == 'dictionary':
                stats['Encrypted'] = True
            else:
                stats['Encrypted'] = False
                self.addError('Bad type for /Encrypt element')
        else:
            stats['Encrypted'] = False
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        return stats

    def getTrailerDictionary(self):
        return self.dict

    def getXrefStreamObject(self):
        return self.streamObject
        
    def inStream(self):
        if self.streamObject != None:
            return True
        else:
            return False

    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True
        
    def setCatalogId(self, newId):
        self.catalogId = newId
        
    def setDictEntry(self, entry, value):
        ret = self.dict.setElement(entry,value)
        if ret[0] == -1:
            errorMessage = ret[1]+' in dictionary element'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return ret

    def setEOFOffset(self, offset):
        self.eofOffset = offset
                    
    def setInfoId(self, newId):
        self.infoId = newId

    def setID(self, newId):
        self.id = newId
        
    def setLastCrossRefSection(self, newOffset):
        self.lastCrossRefSection = newOffset

    def setNumObjects(self, newNumObjects):
        self.numObjects = newNumObjects
        try:
            size = PDFNum(str(newNumObjects))
        except:
            errorMessage = 'Error creating PDFNum'
            if isForceMode:
                self.addError(errorMessage)
                size = PDFNum('0')
            else:
                return (-1,errorMessage)
        ret = self.setDictEntry('/Size', size)
        return ret
            
    def setOffset(self, offset):
        self.offset = offset    

    def setPrevCrossRefSection(self, newOffset):
        try:
            prevSectionObject = PDFNum(str(newOffset))
        except:
            errorMessage = 'Error creating PDFNum'
            if isForceMode:
                self.addError(errorMessage)
                prevSectionObject = PDFNum('0')
            else:
                return (-1,errorMessage)
        ret = self.dict.setElement('/Prev', prevSectionObject)
        if ret[0] == -1:
            errorMessage = ret[1]+' in dictionary element'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return ret

    def setSize(self, newSize):
        self.size = newSize
                
    def setTrailerDictionary(self, newDict):
        self.dict = newDict
        ret = self.update()
        return ret

    def setXrefStreamObject(self, id):
        self.streamObject = id
                
    def toFile(self):
        output = ''
        if self.dict.getNumElements() > 0:
            output += 'trailer' + newLine
            output += self.dict.toFile() + newLine
        output += 'startxref' + newLine
        output += str(self.lastCrossRefSection) + newLine
        output += '%%EOF' + newLine
        return output
    

class PDFFile :
    def __init__(self) :
        self.fileName = ''
        self.path = ''
        self.size = 0
        self.md5 = ''
        self.sha1 = ''
        self.sha256 = ''
        self.detectionRate = []
        self.detectionReport = ''
        self.body = [] # PDFBody[]
        self.binary = False
        self.binaryChars = ''
        self.linearized = False
        self.encryptDict = None
        self.encrypted = False
        self.fileId = ''
        self.encryptionAlgorithms = []
        self.encryptionKey = ''
        self.encryptionKeyLength = 128
        self.ownerPass = ''
        self.userPass = ''
        self.JSCode = ''
        self.crossRefTable = [] # PDFCrossRefSection[]
        self.comments = [] # string[]
        self.version = ''
        self.headerOffset = 0
        self.garbageHeader = ''
        self.suspiciousElements = {}
        self.updates = 0
        self.endLine = ''
        self.trailer = [] # PDFTrailer[]
        self.errors = []
        self.numObjects = 0
        self.numStreams = 0
        self.numEncodedStreams = 0
        self.numDecodingErrors = 0
        self.maxObjectId = 0

    def addBody(self, newBody):
        if newBody != None and isinstance(newBody,PDFBody):
            self.body.append(newBody)
            return (0,'')
        else:
            return (-1,'Bad PDFBody supplied')

    def addCrossRefTableSection(self, newSectionArray):
        if newSectionArray != None and isinstance(newSectionArray,list) and len(newSectionArray) == 2 and (newSectionArray[0] == None or isinstance(newSectionArray[0],PDFCrossRefSection)) and (newSectionArray[1] == None or isinstance(newSectionArray[1],PDFCrossRefSection)):
            self.crossRefTable.append(newSectionArray)
            return (0,'')
        else:
            return (-1,'Bad PDFCrossRefSection array supplied')
    
    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def addNumDecodingErrors(self, num):
        self.numDecodingErrors += num

    def addNumEncodedStreams(self, num):
        self.numEncodedStreams += num
                    
    def addNumObjects(self, num):
        self.numObjects += num
        
    def addNumStreams(self, num):
        self.numStreams += num
        
    def addTrailer(self, newTrailerArray):
        if newTrailerArray != None and isinstance(newTrailerArray,list) and len(newTrailerArray) == 2 and (newTrailerArray[0] == None or isinstance(newTrailerArray[0],PDFTrailer)) and (newTrailerArray[1] == None or isinstance(newTrailerArray[1],PDFTrailer)):
            self.trailer.append(newTrailerArray)
            return (0,'')
        else:
            return (-1,'Bad PDFTrailer array supplied')    

    def createObjectStream(self, version = None, id = None, objectIds = []):
        errorMessage = ''
        tmpStreamObjects = ''
        tmpStreamObjectsInfo = ''
        compressedStream = ''
        compressedDict = {}
        firstObjectOffset = ''
        if version == None:
            version = self.updates
        if objectIds == []:
            objectIds = self.body[version].getObjectsIds()
        numObjects = len(objectIds)
        if id == None:
            id = self.maxObjectId + 1
        for compressedId in objectIds:
            object = self.body[version].getObject(compressedId)
            if object == None:
                errorMessage = 'Object '+str(compressedId)+' cannot be compressed: it does not exist'
                if isForceMode:
                    self.addError(errorMessage)
                    numObjects -= 1
                else:
                    return (-1,errorMessage)
            else:
                objectType = object.getType()
                if objectType == 'stream':
                    errorMessage = 'Stream objects cannot be compressed'
                    self.addError(errorMessage)
                    numObjects -= 1
                else:
                    if objectType == 'dictionary' and object.hasElement('/U') and object.hasElement('/O') and object.hasElement('/R'):
                        errorMessage = 'Encryption dictionaries cannot be compressed'
                        self.addError(errorMessage)
                        numObjects -= 1
                    object.setCompressedIn(id)
                    offset = len(tmpStreamObjects)
                    tmpStreamObjectsInfo += str(compressedId)+' '+str(offset)+' '
                    tmpStreamObjects += object.toFile()
                    ret = self.body[version].setObject(compressedId,object,offset,modification = True)
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(ret[1])
        firstObjectOffset = str(len(tmpStreamObjectsInfo))
        compressedStream = tmpStreamObjectsInfo + tmpStreamObjects
        compressedDict = {'/Type':PDFName('ObjStm'),'/N':PDFNum(str(numObjects)),'/First':PDFNum(firstObjectOffset),'/Length':PDFNum(str(len(compressedStream)))}
        try:
            objectStream = PDFObjectStream('',compressedStream,compressedDict,{},{})
        except Exception,e:
            errorMessage = 'Error creating PDFObjectStream'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1,errorMessage)
        # Filters
        filterObject = PDFName('FlateDecode')
        ret = objectStream.setElement('/Filter',filterObject)
        if ret[0] == -1:
            errorMessage = ret[1]
            self.addError(ret[1])
        objectStreamOffset = self.body[version].getNextOffset()
        if self.encrypted:
            key = computeObjectKey(id, 0, self.encryptionKey, self.encryptionKeyLength/8)
            ret = objectStream.encrypt(key)
            if ret[0] == -1:
                errorMessage = ret[1]
                self.addError(ret[1])
        self.body[version].setNextOffset(objectStreamOffset+len(objectStream.getRawValue()))
        self.body[version].setObject(id,objectStream,objectStreamOffset)
        # Xref stream
        ret = self.createXrefStream(version)
        if ret[0] == -1:
            return ret
        xrefStreamId, xrefStream = ret[1]
        xrefStreamOffset = self.body[version].getNextOffset()
        ret = self.body[version].setObject(xrefStreamId,xrefStream,xrefStreamOffset)
        if ret[0] == -1:
            errorMessage = ret[1]
            self.addError(ret[1])
        self.binary = True
        self.binaryChars = '\xC0\xFF\xEE\xFA\xBA\xDA'
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,id)

    def createXrefStream(self, version, id = None):
        size = 0
        elementsDict = {}
        elementsTrailerDict = {}
        stream = ''
        errorMessage = ''
        indexArray = []
        xrefStream = None
        xrefStreamId = None
        bytesPerFieldArray = []

        if version == None:
            version = self.updates
        # Trailer update
        if len(self.trailer) > version:
            if self.trailer[version][1] != None:
                trailerDict = self.trailer[version][1].getTrailerDictionary()
                if trailerDict != None:
                    elementsTrailerDict = dict(trailerDict.getElements())
                    elementsDict = dict(elementsTrailerDict)
                del(trailerDict)
            if self.trailer[version][0] != None:
                trailerDict = self.trailer[version][0].getTrailerDictionary()
                if trailerDict != None:
                    trailerElementsDict = dict(trailerDict.getElements())
                    if len(trailerElementsDict) > 0:
                        for key in trailerElementsDict:
                            if key not in elementsTrailerDict:
                                elementsTrailerDict[key] = trailerElementsDict[key]
                                elementsDict[key] = trailerElementsDict[key]
                    del(trailerElementsDict)
                del(trailerDict)    
        self.createXrefStreamSection(version)
        if len(self.crossRefTable) <= version:
            errorMessage = 'Cross Reference Table not found'
            self.addError(errorMessage)
            return (-1,errorMessage)
        section = self.crossRefTable[version][1]
        xrefStreamId = section.getXrefStreamObject()
        bytesPerField = section.getBytesPerField()
        for num in bytesPerField:
            try:
                bytesPerFieldArray.append(PDFNum(str(num)))
            except:
                errorMessage = 'Error creating PDFNum in bytesPerField'
                return (-1,errorMessage)
        subsectionsNumber = section.getSubsectionsNumber()
        subsections = section.getSubsectionsArray()
        for subsection in subsections:
            firstObject = subsection.getFirstObject()
            numObjects = subsection.getNumObjects()
            indexArray.append(PDFNum(str(firstObject)))
            indexArray.append(PDFNum(str(numObjects)))
            entries = subsection.getEntries()
            for entry in entries:
                ret = entry.getEntryBytes(bytesPerField)
                if ret[0] == -1:
                    self.addError(ret[1])
                    return (-1,ret[1])
                stream += ret[1]
            if size < firstObject + numObjects:
                size = firstObject + numObjects
        elementsDict['/Type'] = PDFName('XRef')
        elementsDict['/Size'] = PDFNum(str(size))
        elementsTrailerDict['/Size'] = PDFNum(str(size))
        elementsDict['/Index'] = PDFArray('',indexArray)
        elementsDict['/W'] = PDFArray('',bytesPerFieldArray)        
        elementsDict['/Length'] = PDFNum(str(len(stream)))
        try:
            xrefStream = PDFStream('',stream,elementsDict,{})
        except Exception,e:
            errorMessage = 'Error creating PDFStream'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1,errorMessage)
        # Filters
        filterObject = PDFName('FlateDecode')
        if id != None:
            xrefStreamObject = self.getObject(id, version)
            if xrefStreamObject != None:
                filterObject = xrefStreamObject.getElementByName('/Filter')
        ret = xrefStream.setElement('/Filter',filterObject)
        if ret[0] == -1:
            errorMessage = ret[1]
            self.addError(ret[1])
        try:
            trailerStream = PDFTrailer(PDFDictionary(elements=elementsTrailerDict))
        except Exception,e:
            errorMessage = 'Error creating PDFTrailer'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1,errorMessage)
        trailerStream.setXrefStreamObject(xrefStreamId)
        try:
            trailerSection = PDFTrailer(PDFDictionary(elements=dict(elementsTrailerDict)))#PDFDictionary())
        except Exception,e:
            errorMessage = 'Error creating PDFTrailer'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1,errorMessage)
        self.trailer[version] = [trailerSection,trailerStream]
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,[xrefStreamId,xrefStream])
    
    def createXrefStreamSection(self, version = None):
        lastId = 0
        lastFreeObject = 0
        errorMessage = ''
        xrefStreamId = None
        xrefEntries = [PDFCrossRefEntry(0,65535,0)]
        if version == None:
            version = self.updates
        actualStream = self.crossRefTable[version][1]
        if actualStream != None:
             xrefStreamId = actualStream.getXrefStreamObject()
        sortedObjectsByOffset = self.body[version].getObjectsIds()
        sortedObjectsIds = sorted(sortedObjectsByOffset, key=lambda x: int(x))
        indirectObjects = self.body[version].getObjects()
        for id in sortedObjectsIds:
            while id != lastId+1:
                lastFreeEntry = xrefEntries[lastFreeObject]
                lastFreeEntry.setNextObject(lastId+1)
                xrefEntries[lastFreeObject] = lastFreeEntry
                lastFreeObject = lastId+1
                lastId += 1
                xrefEntries.append(PDFCrossRefEntry(0,65535,0))
            indirectObject = indirectObjects[id]
            if indirectObject != None:
                object = indirectObject.getObject()
                if object != None:
                    if object.isCompressed():
                        objectStreamId = object.getCompressedIn()
                        objectStream = self.body[version].getObject(objectStreamId)
                        index = objectStream.getObjectIndex(id)
                        if index == None:
                            errorMessage = 'Compressed object not found in object stream'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1,errorMessage)
                        entry = PDFCrossRefEntry(objectStreamId,index,2)
                    else:
                        offset = indirectObject.getOffset()
                        entry = PDFCrossRefEntry(offset,0,1)
                    xrefEntries.append(entry)
                    lastId = id
        if actualStream == None:
            offset += len(str(object.getRawValue()))
            xrefEntries.append(PDFCrossRefEntry(offset,0,1))
            lastId += 1
            xrefStreamId = lastId
        subsection = PDFCrossRefSubSection(0,lastId+1,xrefEntries)
        xrefSection = PDFCrossRefSection()
        xrefSection.addSubsection(subsection)
        xrefSection.setXrefStreamObject(xrefStreamId)
        xrefSection.setBytesPerField([1,2,2])
        self.crossRefTable[version] = [None,xrefSection]
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,lastId)

    def decrypt(self, password = ''):
        badPassword = False
        fatalError = False
        errorMessage = ''
        passType = None
        encryptionAlgorithms = []
        algorithm = None
        stmAlgorithm = None
        strAlgorithm = None
        embedAlgorithm = None
        computedUserPass = ''
        dictO = '' 
        dictU = ''
        perm = 0
        revision = 0
        fileId = self.getFileId()
        self.removeError(errorType = 'Decryption error')
        if self.encryptDict == None or self.encryptDict[1] == []:
            errorMessage = 'Decryption error: /Encrypt dictionary not found!!'
            if isForceMode:
                self.addError(errorMessage)
            else:
                return (-1,errorMessage)
        # Getting /Encrypt elements
        encDict = self.encryptDict[1]
        # Filter
        if encDict.has_key('/Filter'):
            filter = encDict['/Filter']
            if filter != None and filter.getType() == 'name':
                filter = filter.getValue()
                if filter != '/Standard':
                    errorMessage = 'Decryption error: Filter not supported!!'
                    if isForceMode:
                        fatalError = True
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
            else:
                errorMessage = 'Decryption error: Bad format for /Filter!!'
                if isForceMode:
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Filter not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Algorithm version
        if encDict.has_key('/V'):
            algVersion = encDict['/V']
            if algVersion != None and algVersion.getType() == 'integer':
                algVersion = algVersion.getRawValue()
                if algVersion == 4 or algVersion == 5:
                    stmAlgorithm = ['Identity',40]
                    strAlgorithm = ['Identity',40]
                    embedAlgorithm = ['Identity',40]
                    algorithms = {}
                    if encDict.has_key('/CF'):
                        cfDict = encDict['/CF']
                        if cfDict != None and cfDict.getType() == 'dictionary':
                            cfDict = cfDict.getElements()
                            for cryptFilter in cfDict:
                                cryptFilterDict = cfDict[cryptFilter]
                                if cryptFilterDict != None and cryptFilterDict.getType() == 'dictionary':
                                    algorithms[cryptFilter] = []
                                    defaultKeyLength = 40
                                    cfmValue = ''
                                    cryptFilterDict = cryptFilterDict.getElements()
                                    if cryptFilterDict.has_key('/CFM'):
                                        cfmValue = cryptFilterDict['/CFM']
                                        if cfmValue != None and cfmValue.getType() == 'name':
                                            cfmValue = cfmValue.getValue()
                                            if cfmValue == 'None':
                                                algorithms[cryptFilter].append('Identity')
                                            elif cfmValue == '/V2':
                                                algorithms[cryptFilter].append('RC4')
                                            elif cfmValue == '/AESV2':
                                                algorithms[cryptFilter].append('AES')
                                                defaultKeyLength = 128
                                            elif cfmValue == '/AESV3':
                                                algorithms[cryptFilter].append('AES')
                                                defaultKeyLength = 256
                                            else:
                                                errorMessage = 'Decryption error: Unsupported encryption!!'
                                                if isForceMode:
                                                    self.addError(errorMessage)
                                                else:
                                                    return (-1, errorMessage)
                                        else:
                                            errorMessage = 'Decryption error: Bad format for /CFM!!'
                                            if isForceMode:
                                                cfmValue = ''
                                                self.addError(errorMessage)
                                            else:
                                                return (-1, errorMessage)
                                    if cryptFilterDict.has_key('/Length') and cfmValue != '/AESV3':
                                        # Length is key length in bits
                                        keyLength = cryptFilterDict['/Length']
                                        if keyLength != None and keyLength.getType() == 'integer':
                                            keyLength = keyLength.getRawValue()
                                            if keyLength % 8 != 0:
                                                keyLength = defaultKeyLength
                                                self.addError('Decryption error: Key length not valid!!')
                                            # Check if the length element contains bytes instead of bits as usual
                                            if keyLength < 40:
                                                keyLength *= 8
                                        else:
                                            keyLength = defaultKeyLength
                                            self.addError('Decryption error: Bad format for /Length!!')
                                    else:
                                        keyLength = defaultKeyLength
                                    algorithms[cryptFilter].append(keyLength)
                        else:
                            errorMessage = 'Decryption error: Bad format for /CF!!'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    if encDict.has_key('/StmF'):
                        stmF = encDict['/StmF']
                        if stmF != None and stmF.getType() == 'name':
                            stmF = stmF.getValue()
                            if stmF in algorithms:
                                stmAlgorithm = algorithms[stmF]
                        else:
                            errorMessage = 'Decryption error: Bad format for /StmF!!'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    if encDict.has_key('/StrF'):
                        strF = encDict['/StrF']
                        if strF != None and strF.getType() == 'name':
                            strF = strF.getValue()
                            if strF in algorithms:
                                strAlgorithm = algorithms[strF]
                        else:
                            errorMessage = 'Decryption error: Bad format for /StrF!!'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    if encDict.has_key('/EEF'):
                        eeF = encDict['/EEF']
                        if eeF != None and eeF.getType() == 'name':
                            eeF = eeF.getValue()
                            if eeF in algorithms:
                                embedAlgorithm = algorithms[eeF]
                        else:
                            embedAlgorithm = stmAlgorithm
                            errorMessage = 'Decryption error: Bad format for /EEF!!'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    else:
                        embedAlgorithm = stmAlgorithm
                    if stmAlgorithm not in encryptionAlgorithms:
                        encryptionAlgorithms.append(stmAlgorithm)                        
                    if strAlgorithm not in encryptionAlgorithms:
                        encryptionAlgorithms.append(strAlgorithm)
                    if embedAlgorithm not in encryptionAlgorithms and embedAlgorithm != ['Identity',40]: # Not showing default embedAlgorithm
                        encryptionAlgorithms.append(embedAlgorithm) 
            else:
                errorMessage = 'Decryption error: Bad format for /V!!'
                if isForceMode:
                    algVersion = 0
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Algorithm version not found!!'
            if isForceMode:
                algVersion = 0
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        
        # Key length
        if encDict.has_key('/Length'):
            keyLength = encDict['/Length']
            if keyLength != None and keyLength.getType() == 'integer':
                keyLength = keyLength.getRawValue()
                if keyLength % 8 != 0:
                    keyLength = 40
                    self.addError('Decryption error: Key length not valid!!')
            else:
                keyLength = 40
                self.addError('Decryption error: Bad format for /Length!!')
        else:
            keyLength = 40
        
        # Setting algorithms
        if algVersion == 1 or algVersion == 2:
            algorithm = ['RC4',keyLength]
            stmAlgorithm = strAlgorithm = embedAlgorithm = algorithm
        elif algVersion == 3:
            errorMessage = 'Decryption error: Algorithm not supported!!'
            if isForceMode:
                algorithm = ['Unpublished',keyLength]
                stmAlgorithm = strAlgorithm = embedAlgorithm = algorithm
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        elif algVersion == 5:
            algorithm = ['AES',256]
        if algorithm != None and algorithm not in encryptionAlgorithms:
            encryptionAlgorithms.append(algorithm)
        self.setEncryptionAlgorithms(encryptionAlgorithms)
        
        # Standard encryption: /R /P /O /U
        # Revision
        if encDict.has_key('/R'):
            revision = encDict['/R']
            if revision != None and revision.getType() == 'integer':
                revision = revision.getRawValue()
                if revision < 2 or revision > 5:
                    errorMessage = 'Decryption error: Algorithm revision not supported!!'
                    if isForceMode:
                        fatalError = True
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
            else:
                errorMessage = 'Decryption error: Bad format for /R!!'
                if isForceMode:
                    revision = 0
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Algorithm revision not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Permission
        if encDict.has_key('/P'):
            perm = encDict['/P']
            if perm != None and perm.getType() == 'integer':
                perm = perm.getRawValue()
            else:
                errorMessage = 'Decryption error: Bad format for /P!!'
                if isForceMode:
                    perm = 0
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Permission number not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Owner pass
        if encDict.has_key('/O'):
            dictO = encDict['/O']
            if dictO != None and dictO.getType() in ['string','hexstring']:
                dictO = dictO.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /O!!'
                if isForceMode:
                    dictO = ''
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Owner password not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Owner encrypted string
        if encDict.has_key('/OE'):
            dictOE = encDict['/OE']
            if dictOE != None and dictOE.getType() in ['string','hexstring']:
                dictOE = dictOE.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /OE!!'
                if isForceMode:
                    dictOE = ''
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            dictOE = ''
            if revision == 5:
                errorMessage = 'Decryption error: /OE not found!!'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        # User pass
        if encDict.has_key('/U'):
            dictU = encDict['/U']
            if dictU != None and dictU.getType() in ['string','hexstring']:
                dictU = dictU.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /U!!'
                if isForceMode:
                    dictU = ''
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: User password not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # User encrypted string
        if encDict.has_key('/UE'):
            dictUE = encDict['/UE']
            if dictUE != None and dictUE.getType() in ['string','hexstring']:
                dictUE = dictUE.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /UE!!'
                if isForceMode:
                    dictUE = ''
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            dictUE = ''
            if revision == 5:
                errorMessage = 'Decryption error: /UE not found!!'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        # Metadata encryption
        if encDict.has_key('/EncryptMetadata'):
            encryptMetadata = encDict['/EncryptMetadata']
            if encryptMetadata != None and encryptMetadata.getType() == 'bool':
                encryptMetadata = encryptMetadata.getValue() != 'false'
            else:
                errorMessage = 'Decryption error: Bad format for /EncryptMetadata!!'
                if isForceMode:
                    encryptMetadata = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            encryptMetadata = True
        if not fatalError:
            # Checking user password
            if revision != 5:
                ret = computeUserPass(password, dictO, fileId, perm, keyLength, revision, encryptMetadata)
                if ret[0] != -1:
                    computedUserPass = ret[1]
                else:
                    errorMessage = 'Decryption error: '+ret[1]
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
            if isUserPass(password, computedUserPass, dictU, revision):
                passType = 'USER'
            elif isOwnerPass(password, dictO, dictU, computedUserPass, keyLength, revision):
                passType = 'OWNER'
            else:
                badPassword = True
                if password == '':
                    errorMessage = 'Decryption error: Default user password not working here!!'
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
                else:
                    errorMessage = 'Decryption error: User password not working here!!'
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
        self.setOwnerPass(dictO)
        self.setUserPass(dictU)
        if not fatalError and not badPassword:
            ret = computeEncryptionKey(password, dictO, dictU, dictOE, dictUE, fileId, perm, keyLength, revision, encryptMetadata, passType)
            if ret[0] != -1:
                encryptionKey = ret[1]
            else:
                errorMessage = 'Decryption error: '+ret[1]
                if isForceMode:
                    encryptionKey = ''
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
            self.setEncryptionKey(encryptionKey)
            self.setEncryptionKeyLength(keyLength)
            # Computing objects passwords and decryption
            numKeyBytes = self.encryptionKeyLength/8
            for v in range(self.updates+1):
                indirectObjectsIds = list(set(self.body[v].getObjectsIds()))
                for id in indirectObjectsIds:
                    indirectObject = self.body[v].getObject(id, indirect = True)
                    if indirectObject != None:
                        generationNum = indirectObject.getGenerationNumber()
                        object = indirectObject.getObject()
                        if object != None and not object.isCompressed():
                            objectType = object.getType()
                            if objectType in ['string','hexstring','array','dictionary'] or (objectType == 'stream' and (object.getElement('/Type') == None or (object.getElement('/Type').getValue() not in ['/XRef','/Metadata'] or (object.getElement('/Type').getValue() == '/Metadata' and encryptMetadata)))):
                                key = self.encryptionKey
                                if objectType in ['string','hexstring','array','dictionary']:
                                    if revision < 5:
                                        key = computeObjectKey(id,generationNum,self.encryptionKey,numKeyBytes,strAlgorithm[0])
                                    ret = object.decrypt(key, strAlgorithm[0])
                                else:
                                    if object.getElement('/Type') != None and object.getElement('/Type').getValue() == '/EmbeddedFile':
                                        if revision < 5:
                                            key = computeObjectKey(id,generationNum,self.encryptionKey,numKeyBytes,embedAlgorithm[0])
                                        altAlgorithm = embedAlgorithm[0]
                                    else:
                                        if revision < 5:
                                            key = computeObjectKey(id,generationNum,self.encryptionKey,numKeyBytes,stmAlgorithm[0])
                                        altAlgorithm = stmAlgorithm[0]
                                    ret = object.decrypt(key,strAlgorithm[0], altAlgorithm)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
                                ret = self.body[v].setObject(id,object)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
        if errorMessage != '':
            return (-1, errorMessage)
        return (0,'')

    def deleteObject (self, id) :
        # Remove references too 
        pass
    
    def encodeChars(self):
        errorMessage = ''
        for i in range(self.updates+1):
            ret = self.body[i].encodeChars()
            if ret[0] == -1:
                errorMessage = ret[1]
                self.addError(errorMessage)
            trailerArray = self.trailer[i]
            if trailerArray[0] != None:
                ret = trailerArray[0].encodeChars()
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(errorMessage)
                self.trailer[i] = trailerArray
        if errorMessage != '':
            return (-1, errorMessage)
        return (0,'')
    
    def encrypt(self, password = ''):
        #TODO: AESV2 and V3
        errorMessage = ''
        encryptDictId = None
        encryptMetadata = True
        permissionNum = 1073741823
        dictOE = ''
        dictUE = ''
        ret = self.getTrailer()
        if ret != None:
            trailer,trailerStream = ret[1]
            if trailerStream != None:
                encryptDict = trailerStream.getDictEntry('/Encrypt')
                if encryptDict != None:
                    encryptDictType = encryptDict.getType()
                    if encryptDictType == 'reference':
                        encryptDictId = encryptDict.getId()
                fileId = self.getMD5()
                if fileId == '':
                    fileId = hashlib.md5(str(random.random())).hexdigest()
                md5Object = PDFString(fileId)
                fileIdArray = PDFArray(elements=[md5Object,md5Object])
                trailerStream.setDictEntry('/ID',fileIdArray)
                self.setTrailer([trailer,trailerStream])
            else:
                encryptDict = trailer.getDictEntry('/Encrypt')
                if encryptDict != None:
                    encryptDictType = encryptDict.getType()
                    if encryptDictType == 'reference':
                        encryptDictId = encryptDict.getId()
                fileId = self.getMD5()
                if fileId == '':
                    fileId = hashlib.md5(str(random.random())).hexdigest()
                md5Object = PDFString(fileId)
                fileIdArray = PDFArray(elements=[md5Object,md5Object])
                trailer.setDictEntry('/ID',fileIdArray)
                self.setTrailer([trailer,trailerStream])
                                
            dictO = computeOwnerPass(password,password,128,revision = 3)
            self.setOwnerPass(dictO)
            ret = computeUserPass(password,dictO,fileId,permissionNum,128,revision = 3)
            if ret[0] != -1:
                dictU = ret[1]
            else:
                if isForceMode:
                    self.addError('Decryption error: '+ret[1])
                else:
                    return (-1,'Decryption error: '+ret[1])
            self.setUserPass(dictU)
            ret = computeEncryptionKey(password, dictO, dictU, dictOE, dictUE, fileId, permissionNum, 128, revision = 3, encryptMetadata = encryptMetadata, passwordType = 'USER')
            if ret[0] != -1:
                encryptionKey = ret[1]
            else:
                encryptionKey = ''
                if isForceMode:
                    self.addError('Decryption error: '+ret[1])
                else:
                    return (-1,'Decryption error: '+ret[1])
            self.setEncryptionKey(encryptionKey)
            self.setEncryptionKeyLength(128)
            encryptDict = PDFDictionary(elements = {'/V':PDFNum('2'),'/Length':PDFNum('128'),'/Filter':PDFName('Standard'),
                                                                                        '/R':PDFNum('3'),'/P':PDFNum(str(permissionNum)),'/O':PDFString(dictO),'/U':PDFString(dictU)})
            if encryptDictId != None:
                ret = self.setObject(encryptDictId,encryptDict)
                if ret[0] == -1:
                    errorMessage = '/Encrypt dictionary has not been created/modified'
                    self.addError(errorMessage)
                    return (-1, errorMessage)
            else:
                if trailerStream != None:
                    trailerStream.setDictEntry('/Encrypt',encryptDict)
                else:
                    trailer.setDictEntry('/Encrypt',encryptDict)
                self.setTrailer([trailer,trailerStream])
    
            numKeyBytes = self.encryptionKeyLength/8
            for v in range(self.updates+1):
                indirectObjects = self.body[v].getObjects()
                for id in indirectObjects:
                    indirectObject = indirectObjects[id]
                    if indirectObject != None:
                        generationNum = indirectObject.getGenerationNumber()
                        object = indirectObject.getObject()
                        if object != None and not object.isCompressed():
                            objectType = object.getType()
                            if objectType in ['string','hexstring','array','dictionary'] or (objectType == 'stream' and (object.getElement('/Type') == None or (object.getElement('/Type').getValue() not in ['/XRef','/Metadata'] or (object.getElement('/Type').getValue() == '/Metadata' and encryptMetadata)))):
                                key = computeObjectKey(id,generationNum,self.encryptionKey,numKeyBytes)
                                ret = object.encrypt(key)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
                                ret = self.body[v].setObject(id,object)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
        else:
            errorMessage = 'Trailer not found'
            self.addError(errorMessage)
        if errorMessage != '':
            return (-1, errorMessage)
        self.setEncrypted(True)
        return (0,'')                
    
    def getBasicMetadata(self, version):
        basicMetadata = {}
        
        # Getting creation information
        infoObject = self.getInfoObject(version)
        if infoObject != None:
            author = infoObject.getElementByName('/Author')
            if author != None and author != []:
                basicMetadata['author'] = author.getValue()
            creator = infoObject.getElementByName('/Creator')
            if creator != None and creator != []:
                basicMetadata['creator'] = creator.getValue()
            producer = infoObject.getElementByName('/Producer')
            if producer != None and producer != []:
                basicMetadata['producer'] = producer.getValue()
            creationDate = infoObject.getElementByName('/CreationDate')
            if creationDate != None and creationDate != []:
                basicMetadata['creation'] = creationDate.getValue()
        if not basicMetadata.has_key('author'):
            ids = self.getObjectsByString('<dc:creator>',version)
            if ids != None and ids != []:
                for id in ids:
                    author = self.getMetadataElement(id, version, 'dc:creator')
                    if author != None:
                        basicMetadata['author'] = author
                        break
        if not basicMetadata.has_key('creator'):
            ids = self.getObjectsByString('<xap:CreatorTool>',version)
            if ids != None and ids != []:
                for id in ids:
                    creator = self.getMetadataElement(id, version, 'xap:CreatorTool')
                    if creator != None:
                        basicMetadata['creator'] = creator
                        break
        if not basicMetadata.has_key('creator'):
            ids = self.getObjectsByString('<xmp:CreatorTool>',version)
            if ids != None and ids != []:
                for id in ids:
                    creator = self.getMetadataElement(id, version, 'xmp:CreatorTool')
                    if creator != None:
                        basicMetadata['creator'] = creator
                        break
        if not basicMetadata.has_key('producer'):
            ids = self.getObjectsByString('<pdf:Producer>',version)
            if ids != None and ids != []:
                for id in ids:
                    producer = self.getMetadataElement(id, version, 'pdf:Producer')
                    if producer != None:
                        basicMetadata['producer'] = producer
                        break
        if not basicMetadata.has_key('creation'):
            ids = self.getObjectsByString('<xap:CreateDate>',version)
            if ids != None and ids != []:
                for id in ids:
                    creation = self.getMetadataElement(id, version, 'xap:CreateDate')
                    if creation != None:
                        basicMetadata['creation'] = creation
                        break
        if not basicMetadata.has_key('creation'):
            ids = self.getObjectsByString('<xmp:CreateDate>',version)
            if ids != None and ids != []:
                for id in ids:
                    creation = self.getMetadataElement(id, version, 'xmp:CreateDate')
                    if creation != None:
                        basicMetadata['creation'] = creation
                        break
        if not basicMetadata.has_key('modification'):
            ids = self.getObjectsByString('<xap:ModifyDate>',version)
            if ids != None and ids != []:
                for id in ids:
                    modification = self.getMetadataElement(id, version, 'xap:ModifyDate')
                    if modification != None:
                        basicMetadata['modification'] = modification
                        break
        if not basicMetadata.has_key('modification'):
            ids = self.getObjectsByString('<xmp:ModifyDate>',version)
            if ids != None and ids != []:
                for id in ids:
                    modification = self.getMetadataElement(id, version, 'xmp:ModifyDate')
                    if modification != None:
                        basicMetadata['modification'] = modification
                        break
        return basicMetadata
    
    def getCatalogObject(self, version = None, indirect = False):
        if version == None:
            catalogObjects = []
            catalogIds = self.getCatalogObjectId()
            for id in catalogIds:
                if id != None:
                    catalogObject = self.getObject(id, version, indirect)
                    catalogObjects.append(catalogObject)
                else:
                    catalogObjects.append(None)
            return catalogObjects
        else:
            catalogId = self.getCatalogObjectId(version)
            if catalogId != None:
                catalogObject = self.getObject(catalogId, version, indirect)
                return catalogObject
            else:
                return None

    def getCatalogObjectId(self, version = None):
        if version == None:
            catalogIds = []
            for v in range(self.updates+1):
                catalogId = None
                trailer, streamTrailer = self.trailer[v]
                if trailer != None:
                    catalogId = trailer.getCatalogId()
                if catalogId == None and streamTrailer != None:
                    catalogId = streamTrailer.getCatalogId()
                catalogIds.append(catalogId)
            return catalogIds
        else:
            catalogId = None
            trailer, streamTrailer = self.trailer[version]
            if trailer != None:
                catalogId = trailer.getCatalogId()
            if catalogId == None and streamTrailer != None:
                catalogId = streamTrailer.getCatalogId()
            return catalogId

    def getChangeLog (self, version = None) :
        lastVersionObjects = []
        actualVersionObjects = []
        addedObjects = []
        removedObjects = []
        modifiedObjects = []
        notMatchingObjects = []
        changes = []
        if version == None:
            version = self.updates + 1
        else:
            version += 1
        for i in range(version):
            actualVersionObjects = self.body[i].getObjectsIds()
            if i != 0:
                xrefNewObjects = []
                xrefFreeObjects = []
                crossRefSection = self.crossRefTable[i][0]
                crossRefStreamSection = self.crossRefTable[i][1]
                if crossRefSection != None:
                    xrefNewObjects += crossRefSection.getNewObjectIds()
                    xrefFreeObjects += crossRefSection.getFreeObjectIds()
                if crossRefStreamSection != None:
                    xrefNewObjects += crossRefStreamSection.getNewObjectIds()
                    xrefFreeObjects += crossRefStreamSection.getFreeObjectIds()
                for id in actualVersionObjects:
                    if id not in lastVersionObjects:
                        addedObjects.append(id)
                        lastVersionObjects.append(id)
                    else:
                        modifiedObjects.append(id)
                    if id not in xrefNewObjects or id in xrefFreeObjects:
                        notMatchingObjects.append(id)
                for id in lastVersionObjects:
                    if id not in actualVersionObjects:
                        if id in xrefFreeObjects:
                            removedObjects.append(id)
                            lastVersionObjects.remove(id)
                        if id in xrefNewObjects:
                            notMatchingObjects.append(id)
                changes.append([addedObjects,modifiedObjects,removedObjects,notMatchingObjects])
                addedObjects = []
                removedObjects = []
                modifiedObjects = []
                notMatchingObjects = []
            else:
                lastVersionObjects = actualVersionObjects
        return changes

    def getDetectionRate(self):
        return self.detectionRate

    def getDetectionReport(self):
        return self.detectionReport

    def getEndLine(self):
        return self.endLine
        
    def getEncryptDict(self):
        return self.encryptDict
    
    def getEncryptionAlgorithms(self):
        return self.encryptionAlgorithms
        
    def getEncryptionKey(self):
        return self.encryptionKey
        
    def getEncryptionKeyLength(self):
        return self.encryptionKeyLength
    
    def getErrors(self):
        return self.errors

    def getFileId(self):
        return self.fileId    

    def getFileName(self):
        return self.fileName
    
    def getGarbageHeader(self):
        return self.garbageHeader
    
    def getHeaderOffset(self):
        return self.headerOffset
        
    def getInfoObject(self, version = None, indirect = False):
        if version == None:
            infoObjects = []
            infoIds = self.getInfoObjectId()
            for id in infoIds:
                if id != None:
                    infoObject = self.getObject(id, version, indirect)
                    infoObjects.append(infoObject)
                else:
                    infoObjects.append(None)
            return infoObjects
        else:
            infoId = self.getInfoObjectId(version)
            if infoId != None:
                infoObject = self.getObject(infoId, version, indirect)
                if infoObject == None and version == 0 and self.getLinearized():
                    # Linearized documents can store Info object in the next update
                    infoObject = self.getObject(infoId, None, indirect)
                    return infoObject
                return infoObject
            else:
                return None

    def getInfoObjectId(self, version = None):
        if version == None:
            infoIds = []
            for v in range(self.updates+1):
                infoId = None
                trailer, streamTrailer = self.trailer[v]
                if trailer != None:
                    infoId = trailer.getInfoId()
                if infoId == None and streamTrailer != None:
                    infoId = streamTrailer.getInfoId()
                infoIds.append(infoId)
            else:
                return infoIds
        else:
            infoId = None
            trailer, streamTrailer = self.trailer[version]
            if trailer != None:
                infoId = trailer.getInfoId()
            if infoId == None and streamTrailer != None:
                infoId = streamTrailer.getInfoId()
            return infoId
            
    def getJavascriptCode (self, version = None) :
        JSCode = []
        if version == None:
            for version in range(self.updates+1):
                JSCode += self.body[version].getJSCode()
        else:
            if version <= self.updates and not version < 0:
                JSCode = self.body[version].getJSCode()
        return JSCode 
    
    def getLinearized(self):
        return self.linearized

    def getMD5(self):
        return self.md5
    
    def getMetadata (self, version = None):
        matchingObjects = self.getObjectsByString('/Metadata', version)
        return matchingObjects
    
    def getMetadataElement(self, objectId, version, element):    
        metadataObject = self.getObject(objectId,version)
        if metadataObject != None:
            if metadataObject.getType() == 'stream': 
                stream = metadataObject.getStream()
                matches = re.findall('<'+element+'>(.*)</'+element+'>',stream)
                if matches != []:
                    return matches[0]
                else:
                    return None
            else:
                return None
        else:
            return None

    def getNumUpdates(self):
        return self.updates
            
    def getObject (self, id, version = None, indirect = False) :
        ''' 
            Returns the specified object
        '''
        if version == None:
            for i in range(self.updates,-1,-1):
                if indirect:
                    object = self.body[i].getIndirectObject(id)
                else:
                    object = self.body[i].getObject(id)
                if object == None:
                    continue
                else:
                    return object
            else:
                return None
        else:
            if version > self.updates or version < 0:
                return None
            if indirect:
                return self.body[version].getIndirectObject(id)
            else:
                return self.body[version].getObject(id)    

    def getObjectsByString (self, toSearch, version = None) :
        ''' Returns the object containing the specified string. '''
        matchedObjects = []
        if version == None:
            for i in range(self.updates + 1):
                matchedObjects.append(self.body[i].getObjectsByString(toSearch))
            return matchedObjects
        else:
            if version > self.updates or version < 0:
                return None 
            return self.body[version].getObjectsByString(toSearch)
        
    def getOffsets(self, version = None):
        offsetsArray = []
        
        if version == None:
            versions = range(self.updates+1)
        else:
            versions = [version]
            
        for version in versions:
            offsets = {}
            trailer = None
            xref = None
            objectStreamsOffsets = {}
            indirectObjects = self.body[version].getObjects()
            sortedObjectsIds = self.body[version].getObjectsIds()
            compressedObjects = self.body[version].getCompressedObjects()
            objectStreams = self.body[version].getObjectStreams()
            ret = self.getXrefSection(version)
            if ret != None:
                xref, streamXref = ret[1]
            ret = self.getTrailer(version)
            if ret != None:
                trailer, streamTrailer = ret[1]
            if objectStreams != []:
                for objStream in objectStreams:
                    if objStream in indirectObjects:
                        indirectObject = indirectObjects[objStream]
                        if indirectObject != None:
                            objectStreamsOffsets[objStream] = indirectObject.getOffset()
            if version == 0:
                offsets['header'] = (self.headerOffset,0)
            for id in sortedObjectsIds:
                indirectObject = indirectObjects[id]
                if indirectObject != None:
                    objectOffset = indirectObject.getOffset()
                    object = indirectObject.getObject()
                    if object != None and object.isCompressed():
                        compressedIn = object.getCompressedIn()
                        if compressedIn in objectStreamsOffsets:
                            objectOffset = objectStreamsOffsets[compressedIn] + objectOffset + 20    
                    size = indirectObject.getSize()
                    if offsets.has_key('objects'):
                        offsets['objects'].append((id,objectOffset,size))
                    else:
                        offsets['objects'] = [(id,objectOffset,size)]
            if xref != None:
                xrefOffset = xref.getOffset()
                xrefSize = xref.getSize()
                offsets['xref'] = (xrefOffset, xrefSize)
            else:
                offsets['xref'] = None
            if trailer != None:
                trailerOffset = trailer.getOffset()
                trailerSize = trailer.getSize()
                eofOffset = trailer.getEOFOffset()
                offsets['trailer'] = (trailerOffset,trailerSize)
                offsets['eof'] = (eofOffset,0)
            else:
                offsets['trailer'] = None
                offsets['eof'] = None
            offsets['compressed'] = compressedObjects
            offsetsArray.append(offsets)
        return offsetsArray

    def getOwnerPass(self):
        return self.ownerPass
    
    def getPath(self):
        return self.path
    
    def getReferencesIn (self, id, version = None) :
        ''' 
            Get the references in an object
        '''
        if version == None:
            for i in range(self.updates,-1,-1):
                indirectObjectsDict = self.body[i].getObjects()
                if indirectObjectsDict.has_key(id):
                    indirectObject = indirectObjectsDict[id]
                    if indirectObject == None:
                        return None
                    else:
                        return indirectObject.getReferences()
            else:
                return None
        else:
            if version > self.updates or version < 0:
                return None
            indirectObjectsDict = self.body[version].getObjects()
            if indirectObjectsDict.has_key(id):
                indirectObject = indirectObjectsDict[id]
                if indirectObject == None:
                    return None
                else:
                    return indirectObject.getReferences()
            else:
                return None
    
    def getReferencesTo (self, id, version = None) :
        ''' 
            Get the references to the specified object in the document
        '''
        matchedObjects = []
        if version == None:
            for i in range(self.updates + 1):
                indirectObjectsDict = self.body[i].getObjects()
                for indirectObject in indirectObjectsDict.values():
                    if indirectObject != None:
                        object = indirectObject.getObject()
                        if object != None:
                            value = object.getValue()
                            if re.findall('\D'+str(id)+'\s{1,3}\d{1,3}\s{1,3}R', value) != []:
                                matchedObjects.append(indirectObject.id)
        else:
            if version > self.updates or version < 0:
                return None
            indirectObjectsDict = self.body[version].getObjects()
            for indirectObject in indirectObjectsDict.values():
                if indirectObject != None:
                    object = indirectObject.getObject()
                    if object != None:
                        value = object.getValue()
                        if re.findall('\D'+str(id)+'\s{1,3}\d{1,3}\s{1,3}R', value) != []:
                            matchedObjects.append(indirectObject.id)
        return matchedObjects

    def getSHA1(self):
        return self.sha1
    
    def getSHA256(self):
        return self.sha256
    
    def getSize(self):
        return self.size
        
    def getStats (self):
        stats = {}
        stats['File'] = self.fileName
        stats['MD5'] = self.md5
        stats['SHA1'] = self.sha1
        stats['SHA256'] = self.sha256
        stats['Size'] = str(self.size)
        stats['Detection'] = self.detectionRate
        stats['Detection report'] = self.detectionReport
        stats['Version'] = self.version
        stats['Binary'] = str(self.binary)
        stats['Linearized'] = str(self.linearized)
        stats['Encrypted'] = str(self.encrypted)
        stats['Encryption Algorithms'] = self.encryptionAlgorithms
        stats['Updates'] = str(self.updates)
        stats['Objects'] = str(self.numObjects)
        stats['Streams'] = str(self.numStreams)
        stats['Comments'] = str(len(self.comments))
        stats['Errors'] = self.errors
        stats['Versions'] = []
        for version in range(self.updates+1):
            statsVersion = {}
            catalogId = None
            infoId = None
            trailer, streamTrailer = self.trailer[version]
            if trailer != None:
                catalogId = trailer.getCatalogId()
                infoId = trailer.getInfoId()
            if catalogId == None and streamTrailer != None:
                catalogId = streamTrailer.getCatalogId()
            if infoId == None and streamTrailer != None:
                infoId = streamTrailer.getInfoId()
            if catalogId != None:
                statsVersion['Catalog'] = str(catalogId)
            else:
                statsVersion['Catalog'] = None
            if infoId != None:
                statsVersion['Info'] = str(infoId)
            else:
                statsVersion['Info'] = None
            objectsById = sorted(self.body[version].getObjectsIds(), key=lambda x: int(x))
            statsVersion['Objects'] = [str(self.body[version].getNumObjects()),objectsById]
            if self.body[version].containsCompressedObjects():
                compressedObjects = self.body[version].getCompressedObjects()
                statsVersion['Compressed Objects'] = [str(len(compressedObjects)),compressedObjects]
            else:
                statsVersion['Compressed Objects'] = None
            numFaultyObjects = self.body[version].getNumFaultyObjects()
            if numFaultyObjects > 0:
                statsVersion['Errors'] = [str(numFaultyObjects),self.body[version].getFaultyObjects()]
            else:
                statsVersion['Errors'] = None
            numStreams = self.body[version].getNumStreams()
            statsVersion['Streams'] = [str(numStreams),self.body[version].getStreams()]
            if self.body[version].containsXrefStreams():
                xrefStreams = self.body[version].getXrefStreams()
                statsVersion['Xref Streams'] = [str(len(xrefStreams)),xrefStreams]
            else:
                statsVersion['Xref Streams'] = None
            if self.body[version].containsObjectStreams():
                objectStreams = self.body[version].getObjectStreams()
                statsVersion['Object Streams'] = [str(len(objectStreams)),objectStreams]
            else:
                statsVersion['Object Streams'] = None
            if numStreams > 0:
                statsVersion['Encoded'] = [str(self.body[version].getNumEncodedStreams()),self.body[version].getEncodedStreams()]
                numDecodingErrors = self.body[version].getNumDecodingErrors()
                if numDecodingErrors > 0:
                    statsVersion['Decoding Errors'] = [str(numDecodingErrors),self.body[version].getFaultyStreams()]
                else:
                    statsVersion['Decoding Errors'] = None
            else:
                statsVersion['Encoded'] = None
            containingJS = self.body[version].getContainingJS()
            if len(containingJS) > 0:
                statsVersion['Objects with JS code'] = [str(len(containingJS)),containingJS]
            else:
                statsVersion['Objects with JS code'] = None
            actions = self.body[version].getSuspiciousActions()
            events = self.body[version].getSuspiciousEvents()
            vulns = self.body[version].getVulns()
            elements = self.body[version].getSuspiciousElements()
            urls = self.body[version].getURLs()
            if len(events) > 0:
                statsVersion['Events'] = events
            else:
                statsVersion['Events'] = None
            if len(actions) > 0:
                statsVersion['Actions'] = actions
            else:
                statsVersion['Actions'] = None
            if len(vulns) > 0:
                statsVersion['Vulns'] = vulns
            else:
                statsVersion['Vulns'] = None
            if len(elements) > 0:
                statsVersion['Elements'] = elements
            else:
                statsVersion['Elements'] = None
            if len(urls) > 0:
                statsVersion['URLs'] = urls
            else:
                statsVersion['URLs'] = None
            stats['Versions'].append(statsVersion)
        return stats

    def getSuspiciousComponents (self) :
        pass
            
    def getTrailer (self, version = None) :
        if version == None:
            for i in range(self.updates,-1,-1):
                trailerArray = self.trailer[i]
                if trailerArray == None or trailerArray == []:
                    continue
                else:
                    return (i,trailerArray)
            else:
                #self.addError('Trailer not found in file')
                return None
        else:
            if version > self.updates or version < 0:
                #self.addError('Bad version getting trailer')
                return None
            trailerArray = self.trailer[version]
            if trailerArray == None or trailerArray == []:
                return None
            else:
                return (version,trailerArray)

    def getTree (self, version = None) :
        '''
            Returns the logical structure (tree) of the document
        '''
        tree = []
        
        if version == None:
            versions = range(self.updates+1)
        else:
            versions = [version]
            
        for version in versions:
            objectsIn = {}
            trailer = None
            streamTrailer = None
            catalogId = None
            infoId = None
            ids = self.body[version].getObjectsIds()
            ret = self.getTrailer(version)
            if ret != None:
                trailer, streamTrailer = ret[1]
            # Getting info and catalog id
            if trailer != None:
                catalogId = trailer.getCatalogId()
                infoId = trailer.getInfoId()
            if catalogId == None and streamTrailer != None:
                catalogId = streamTrailer.getCatalogId()
            if infoId == None and streamTrailer != None: 
                infoId = streamTrailer.getInfoId()
            for id in ids:
                referencesIds = []
                object = self.getObject(id, version)
                if object != None:
                    type = object.getType()    
                    if type == 'dictionary' or type == 'stream':
                        elements = object.getElements()
                        if infoId == id:
                            type = '/Info'
                        else:
                            dictType = object.getDictType()
                            if dictType != '':
                                type = dictType
                            else:
                                if type == 'dictionary' and len(elements) == 1:
                                    type = elements.keys()[0]
                    references = self.getReferencesIn(id, version)
                    for i in range(len(references)):
                        referencesIds.append(int(references[i].split()[0]))
                    if references == None:
                        objectsIn[id] = (type, [])
                    else:
                        objectsIn[id] = (type, referencesIds)
            tree.append([catalogId, objectsIn])
        return tree

    def getUpdates(self):
        return self.updates    

    def getURLs (self, version = None) :
        urls = []
        if version == None:
            for version in range(self.updates+1):
                urls += self.body[version].getURLs()
        else:
            if version <= self.updates and not version < 0:
                urls = self.body[version].getURLs()
        return urls 

    def getUserPass(self):
        return self.userPass
    
    def getVersion(self):
        return self.version

    def getXrefSection (self, version = None) :
        if version == None:
            for i in range(self.updates,-1,-1):
                xrefArray = self.crossRefTable[i]
                if xrefArray == None or xrefArray == []:
                    continue
                else:
                    return (i,xrefArray)
            else:
                #self.addError('Xref section not found in file')
                return None
        else:
            if version > self.updates or version < 0:
                return None
            xrefArray = self.crossRefTable[version]
            if xrefArray == None or xrefArray == []:
                return None
            else:
                return (version,xrefArray)
                
    def headerToFile(self, malformedOptions, headerFile):
        headerGarbage = ''
        if MAL_ALL in malformedOptions or MAL_HEAD in malformedOptions:
            if headerFile == None:
                if self.garbageHeader == '':
                    headerGarbage = 'MZ'+'_'*100
                else:
                    headerGarbage = self.garbageHeader
            else:
                headerGarbage = open(headerFile,'rb').read()
            headerGarbage += newLine
        if MAL_ALL in malformedOptions or MAL_BAD_HEAD in malformedOptions:
            output = headerGarbage + '%PDF-1.\0' + newLine
        else:
            output = headerGarbage + '%PDF-' + self.version + newLine
        if self.binary or headerGarbage != '':
            self.binary = True
            self.binaryChars = '\xC0\xFF\xEE\xFA\xBA\xDA'
            output += '%' + self.binaryChars + newLine
        return output
    
    def isEncrypted(self):
        return self.encrypted

    def makePDF(self, pdfType, content):
        offset = 0
        numObjects = 3
        self.version = '1.7'
        xrefEntries = []
        staticIndirectObjectSize = 13+3*len(newLine)
        self.setHeaderOffset(offset)
        if pdfType == 'open_action_js':
            self.binary = True
            self.binaryChars = '\xC0\xFF\xEE\xFA\xBA\xDA'
            offset = 16
        else:
            offset = 10
            
        # Body
        body = PDFBody()
        xrefEntries.append(PDFCrossRefEntry(0,65535,'f'))
        # Catalog (1)
        catalogElements = {'/Type':PDFName('Catalog'),'/Pages':PDFReference('2')}
        if pdfType == 'open_action_js':
            catalogElements['/OpenAction'] = PDFReference('4')
        catalogDictionary = PDFDictionary(elements=catalogElements)
        catalogSize = staticIndirectObjectSize + len(catalogDictionary.getRawValue())
        body.setObject(object = catalogDictionary, offset = offset)
        xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
        offset += catalogSize
        # Pages root node (2)
        pagesDictionary = PDFDictionary(elements={'/Type':PDFName('Pages'),'/Kids':PDFArray(elements=[PDFReference('3')]),'/Count':PDFNum('1')})
        pagesSize = len(pagesDictionary.getRawValue())+staticIndirectObjectSize
        body.setObject(object = pagesDictionary, offset = offset)
        xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
        offset += pagesSize
        # Page node (3)
        mediaBoxArray = PDFArray(elements=[PDFNum('0'),PDFNum('0'),PDFNum('600'),PDFNum('800')])
        pageDictionary = PDFDictionary(elements={'/Type':PDFName('Page'),'/Parent':PDFReference('2'),'/MediaBox':mediaBoxArray,'/Resources':PDFDictionary()})
        pageSize = len(pageDictionary.getRawValue())+staticIndirectObjectSize
        body.setObject(object = pageDictionary, offset = offset)
        xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
        offset += pageSize
        if pdfType == 'open_action_js':
            # Action object (4)
            actionDictionary = PDFDictionary(elements={'/Type':PDFName('Action'),'/S':PDFName('JavaScript'),'/JS':PDFReference('5')})
            actionSize = len(actionDictionary.getRawValue())+staticIndirectObjectSize
            body.setObject(object = actionDictionary, offset = offset)
            xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
            offset += actionSize
            # JS stream (5)
            try:
                jsStream = PDFStream(rawStream = content, elements = {'/Length':PDFNum(str(len(content)))})
            except Exception,e:
                errorMessage = 'Error creating PDFStream'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
            ret = jsStream.setElement('/Filter',PDFName('FlateDecode'))
            if ret[0] == -1:
                self.addError(ret[1])
                return ret
            jsSize = len(jsStream.getRawValue())+staticIndirectObjectSize
            ret = body.setObject(object = jsStream, offset = offset)
            if ret[0] == -1:
                self.addError(ret[1])
                return ret
            xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
            offset += jsSize
            numObjects = 5
        body.setNextOffset(offset)
        self.addBody(body)
        self.addNumObjects(body.getNumObjects())
        self.addNumStreams(body.getNumStreams())
        self.addNumEncodedStreams(body.getNumEncodedStreams())
        self.addNumDecodingErrors(body.getNumDecodingErrors())
        
        # xref table
        subsection = PDFCrossRefSubSection(0,numObjects+1,xrefEntries)
        xrefSection = PDFCrossRefSection()
        xrefSection.addSubsection(subsection)
        xrefSection.setOffset(offset)
        xrefOffset = offset
        xrefSectionSize = len(xrefEntries)*20+10
        xrefSection.setSize(xrefSectionSize)
        offset += xrefSectionSize
        self.addCrossRefTableSection([xrefSection,None])
        
        # Trailer
        trailerDictionary = PDFDictionary(elements={'/Size':PDFNum(str(numObjects+1)),'/Root':PDFReference('1')})
        trailerSize = len(trailerDictionary.getRawValue())+25
        trailer = PDFTrailer(trailerDictionary,str(xrefOffset))
        trailer.setOffset(offset)
        trailer.setSize(trailerSize)
        trailer.setEOFOffset(offset+trailerSize)
        self.addTrailer([trailer,None])
        self.setSize(offset+trailerSize+5)
        self.updateStats()
        return (0,'')

    def replace(self, string1, string2):
        errorMessage = ''
        stringFound = False
        for i in range(self.updates + 1):
            objects = self.getObjectsByString(string1,i)
            for id in objects:
                object = self.getObject(id, i)
                if object != None:
                    ret = object.replace(string1, string2)
                    if ret[0] == -1 and not stringFound:
                        errorMessage = ret[1]
                    else:
                        stringFound = True
                        ret = self.setObject(id, object, i)
                        if ret[0] == -1:
                            errorMessage = ret[1]
        if not stringFound:
            return (-1,'String not found')
        if errorMessage != '':
            return (-1, errorMessage)
        else:
            return (0,'')

    def removeError(self, errorMessage = '', errorType = None):
        '''
            Removes the error message from the errors array. If an errorType is given, then all the error messages belonging to this type are removed.
        
            @param errorMessage: The error message to be removed (string)
            @param errorType: All the error messages of this type will be removed (string) 
        '''
        if errorMessage in self.errors:
            self.errors.remove(errorMessage)
        if errorType != None:
            lenErrorType = len(errorType)
            for error in self.errors:
                if error[:lenErrorType] == errorType:
                    self.errors.remove(error)
                
    def save(self, filename, version = None, malformedOptions = [], headerFile = None):
        maxId = 0
        offset = 0
        lastXrefSectionOffset = 0
        prevXrefSectionOffset = 0
        prevXrefStreamOffset = 0
        indirectObjects = {}
        xrefStreamObjectId = None
        xrefStreamObject = None
        try:
            if version == None:
                version = self.updates
            outputFileContent = self.headerToFile(malformedOptions,headerFile)
            offset = len(outputFileContent)
            for v in range(version+1):
                xrefStreamObjectId = None
                xrefStreamObject = None
                sortedObjectsIds = self.body[v].getObjectsIds()
                indirectObjects = self.body[v].getObjects()
                section, streamSection = self.crossRefTable[v]
                trailer, streamTrailer = self.trailer[v]
                if section != None:
                    numSubSectionsInXref = section.getSubsectionsNumber()
                else:
                    numSubSectionsInXref = 0
                if streamSection != None:
                    numSubSectionsInXrefStream = streamSection.getSubsectionsNumber()
                else:
                    numSubSectionsInXrefStream = 0
                if streamSection != None:
                    xrefStreamObjectId = streamSection.getXrefStreamObject()
                    if indirectObjects.has_key(xrefStreamObjectId):
                        xrefStreamObject = indirectObjects[xrefStreamObjectId]
                        sortedObjectsIds.remove(xrefStreamObjectId)
                for id in sortedObjectsIds:
                    if id > maxId:
                        maxId = id
                    indirectObject = indirectObjects[id]
                    if indirectObject != None:
                        object = indirectObject.getObject()
                        if object != None:
                            objectType = object.getType()
                            if not object.isCompressed():
                                indirectObject.setOffset(offset)
                                if numSubSectionsInXref != 0:
                                    ret = section.updateOffset(id, offset)
                                    if ret[0] == -1:
                                        ret = section.addEntry(id,PDFCrossRefEntry(offset,0,'n'))
                                        if ret[0] == -1:
                                            self.addError(ret[1])
                                if numSubSectionsInXrefStream != 0:
                                    ret = streamSection.updateOffset(id, offset)
                                    if ret[0] == -1:
                                        ret = streamSection.addEntry(id,PDFCrossRefEntry(offset,0,'n'))
                                        if ret[0] == -1:
                                            self.addError(ret[1])
                                objectFileOutput = indirectObject.toFile()
                                if objectType == 'stream' and MAL_ESTREAM in malformedOptions:
                                    objectFileOutput = objectFileOutput.replace(newLine+'endstream','')
                                elif MAL_ALL in malformedOptions or MAL_EOBJ in malformedOptions:
                                    objectFileOutput = objectFileOutput.replace(newLine+'endobj','')
                                outputFileContent += objectFileOutput
                                offset = len(outputFileContent)
                                indirectObject.setSize(offset-indirectObject.getOffset())
                                indirectObjects[id] = indirectObject
                    
                if xrefStreamObject != None:
                    if numSubSectionsInXref != 0:
                        ret = section.updateOffset(xrefStreamObjectId, offset)
                        if ret[0] == -1:
                            self.addError(ret[1])
                    ret = streamSection.updateOffset(xrefStreamObjectId, offset)
                    if ret[0] == -1:
                        self.addError(ret[1])
                    xrefStreamObject.setOffset(offset)
                    if xrefStreamObjectId > maxId:
                        maxId = xrefStreamObjectId
                    streamSection.setSize(maxId+1)
                    if streamTrailer != None:
                        streamTrailer.setNumObjects(maxId+1)
                        if prevXrefStreamOffset != 0:
                            streamTrailer.setPrevCrossRefSection(prevXrefStreamOffset)
                        self.trailer[v][1] = streamTrailer
                    self.crossRefTable[v][1] = streamSection
                    ret = self.createXrefStream(v, xrefStreamObjectId)
                    if ret[0] == -1:
                        return (-1,ret[1])
                    xrefStreamObjectId,newXrefStream = ret[1]
                    xrefStreamObject.setObject(newXrefStream)
                    objectFileOutput = xrefStreamObject.toFile()
                    if MAL_ALL in malformedOptions or MAL_ESTREAM in malformedOptions:
                        objectFileOutput = objectFileOutput.replace(newLine+'endstream','')
                    outputFileContent += objectFileOutput
                    prevXrefStreamOffset = offset
                    lastXrefSectionOffset = offset
                    offset = len(outputFileContent)
                    xrefStreamObject.setSize(offset-xrefStreamObject.getOffset())
                    indirectObjects[xrefStreamObjectId] = xrefStreamObject
                self.body[v].setNextOffset(offset)    
                                        
                if section != None and MAL_ALL not in malformedOptions and MAL_XREF not in malformedOptions:
                    section.setOffset(offset)
                    lastXrefSectionOffset = offset
                    outputFileContent += section.toFile()
                    offset = len(outputFileContent)
                    section.setSize(offset-section.getOffset())
                    self.crossRefTable[v][0] = section
                    
                if trailer != None:
                    trailer.setLastCrossRefSection(lastXrefSectionOffset)
                    trailer.setOffset(offset)
                    if trailer.getCatalogId() != None and trailer.getSize() != 0:
                        trailer.setNumObjects(maxId+1)
                        if prevXrefSectionOffset != 0:
                            trailer.setPrevCrossRefSection(prevXrefSectionOffset)
                    outputFileContent += trailer.toFile()
                    offset = len(outputFileContent)
                    trailer.setSize(offset-trailer.getOffset())
                    self.trailer[v][0] = trailer
                prevXrefSectionOffset = lastXrefSectionOffset
                self.body[v].setObjects(indirectObjects)
                offset = len(outputFileContent)
            open(filename,'wb').write(outputFileContent)
            self.setMD5(hashlib.md5(outputFileContent).hexdigest())
            self.setSize(len(outputFileContent))
            self.path = os.path.realpath(filename)
            self.fileName = filename
        except:
            return (-1,'Unspecified error')
        return (0,'')

    def setDetectionRate(self, newRate):
        self.detectionRate = newRate

    def setDetectionReport(self, detectionReportLink):
        self.detectionReport = detectionReportLink
        
    def setEncryptDict(self, dict):
        self.encryptDict = dict

    def setEncrypted(self, status):
        self.encrypted = status    

    def setEncryptionAlgorithms(self, encryptionAlgorithms):
        self.encryptionAlgorithms = encryptionAlgorithms

    def setEncryptionKey(self, key):
        self.encryptionKey = key    

    def setEncryptionKeyLength(self, length):
        self.encryptionKeyLength = length
                            
    def setEndLine(self, eol):
        self.endLine = eol    

    def setFileId(self, fid):
        self.fileId = fid
        
    def setFileName(self, name):
        self.fileName = name

    def setGarbageHeader(self, garbage):
        self.garbageHeader = garbage

    def setHeaderOffset(self, offset):
        self.headerOffset = offset

    def setLinearized(self, status):
        self.linearized = status

    def setMaxObjectId(self, id):
        if int(id) > self.maxObjectId:
            self.maxObjectId = int(id)
        
    def setMD5(self, md5):
        self.md5 = md5
                
    def setObject (self, id, object, version = None, mod = False):
        errorMessage = ''
        if object == None:
            return (-1,'Object is None')
        if version == None:
            for i in range(self.updates,-1,-1):
                ret = self.body[i].setObject(id, object, modification = mod)
                if ret[0] == -1:
                    errorMessage = ret[1]
                else:
                    objectType = object.getType()
                    if objectType == 'dictionary' and object.hasElement('/Linearized'):
                        self.setLinearized(True)
                    return ret
            else:
                return (-1, errorMessage)
        else:
            if version > self.updates or version < 0:
                return (-1,'Bad file version')
            ret = self.body[version].setObject(id, object, modification = mod)
            if ret[0] == -1:
                self.addError(ret[1])
                return (-1,ret[1])
            else:
                objectType = object.getType()
                if objectType == 'dictionary' and object.hasElement('/Linearized'):
                    self.setLinearized(True)
                return ret

    def setOwnerPass(self, password):
        self.ownerPass = password    
        
    def setPath(self, path):
        self.path = path

    def setSHA1(self, sha1):
        self.sha1 = sha1

    def setSHA256(self, sha256):
        self.sha256 = sha256

    def setSize(self, size):
        self.size = size
                
    def setTrailer(self, trailerArray, version = None):
        errorMessage = ''
        if version == None:
            for i in range(self.updates,-1,-1):
                if len(self.trailer) > i:
                    self.trailer[i] = trailerArray
                else:
                    errorMessage = 'Trailer not found'
                    self.addError(errorMessage)
        else:
            if version > self.updates or version < 0:
                return (-1,'Bad file version')
            self.trailer[version] = trailerArray
        if errorMessage != '':
            return (-1, errorMessage)
        return (0,'')

    def setUpdates(self, num):
        self.updates = num    

    def setUserPass(self, password):
        self.userPass = password

    def setVersion(self, version):
        self.version = version
                
    def updateStats(self, recursiveUpdate = False):
        self.numObjects = 0
        self.numStreams = 0
        self.numEncodedStreams = 0
        self.numDecodingErrors = 0
        self.encrypted = False
        
        for v in range(self.updates+1):
            if recursiveUpdate:
                #TODO
                self.updateBody(v)
                self.updateCrossRefTable(v)
                self.updateTrailer(v)
            
            #body.updateObjects()
            self.addNumObjects(self.body[v].getNumObjects())
            self.addNumStreams(self.body[v].getNumStreams())
            self.addNumEncodedStreams(self.body[v].getNumEncodedStreams())
            self.addNumDecodingErrors(self.body[v].getNumDecodingErrors())
            trailer, streamTrailer = self.trailer[v]
            if trailer != None:
                if trailer.getDictEntry('/Encrypt') != None:
                    self.setEncrypted(True)
            if streamTrailer != None:
                if streamTrailer.getDictEntry('/Encrypt') != None:
                    self.setEncrypted(True)
        return (0,'')

    def updateBody (self, version) :
        #TODO
        pass
    
    def updateCrossRefTable (self, version) :
        #TODO
        pass
    
    def updateTrailer (self, version) :
        #TODO
        pass


class PDFParser :
    def __init__(self) :
        self.commentChar = '%'
        self.comments = []
        self.delimiters = [('<<','>>','dictionary'),('(',')','string'),('<','>','hexadecimal'),('[',']','array'),('{','}',''),('/','','name'),('%','','comment')]
        self.fileParts = []
        self.charCounter = 0    
    
    def parse (self, fileName, forceMode = False, looseMode = False, manualAnalysis = False) :
        '''
            Main method to parse a PDF document
            @param fileName The name of the file to be parsed
            @param forceMode Boolean to specify if ignore errors or not. Default value: False.
            @param looseMode Boolean to set the loose mode when parsing objects. Default value: False.
            @return A PDFFile instance
        '''
        global isForceMode, pdfFile, isManualAnalysis
        isFirstBody = True
        linearizedFound = False
        errorMessage = ''
        versionLine = ''
        binaryLine = ''
        headerOffset = 0
        garbageHeader = ''
        pdfFile = PDFFile()
        pdfFile.setPath(fileName)
        pdfFile.setFileName(os.path.basename(fileName))
        isForceMode = forceMode
        isManualAnalysis = manualAnalysis
        
        # Reading the file header
        file = open(fileName,'rb')
        for line in file:
            if versionLine == '':
                pdfHeaderIndex = line.find('%PDF-')
                psHeaderIndex = line.find('%!PS-Adobe-')
                if pdfHeaderIndex != -1 or psHeaderIndex != -1:
                    index = line.find('\r')
                    if index != -1 and index+1 < len(line) and line[index+1] != '\n':
                        index += 1
                        versionLine = line[:index]
                        binaryLine = line[index:]
                        break
                    else:
                        versionLine = line
                    if pdfHeaderIndex != -1:
                        headerOffset += pdfHeaderIndex
                    else:
                        headerOffset += psHeaderIndex
                    pdfFile.setHeaderOffset(headerOffset)
                else:
                    garbageHeader += line
            else:
                binaryLine = line
                break
            headerOffset += len(line)
        file.close()
        
        # Getting the specification version
        versionLine = versionLine.replace('\r','')
        versionLine = versionLine.replace('\n','')
        matchVersion = re.findall('%(PDF-|!PS-Adobe-\d{1,2}\.\d{1,2}\sPDF-)(\d{1,2}\.\d{1,2})',versionLine)
        if matchVersion == []:
            if forceMode:
                pdfFile.setVersion(versionLine)
                pdfFile.addError('Bad PDF header')
                errorMessage = 'Bad PDF header'
            else:
                sys.exit('Error: Bad PDF header!! (' + versionLine + ')')
        else:
            pdfFile.setVersion(matchVersion[0][1])
        if garbageHeader != '':
            pdfFile.setGarbageHeader(garbageHeader)
            
        # Getting the end of line
        if len(binaryLine) > 3:
            if binaryLine[-2:] == '\r\n':
                pdfFile.setEndLine('\r\n')
            else:
                if binaryLine[-1] == '\r':
                    pdfFile.setEndLine('\r')
                elif binaryLine[-1] == '\n':
                    pdfFile.setEndLine('\n')
                else:
                    pdfFile.setEndLine('\n')
        
            # Does it contain binary characters??
            if binaryLine[0] == '%' and ord(binaryLine[1]) >= 128 and ord(binaryLine[2]) >= 128 and ord(binaryLine[3]) >= 128 and ord(binaryLine[4]) >= 128:
                pdfFile.binary = True
                pdfFile.binaryChars = binaryLine[1:5]
            else:
                pdfFile.binary = False
            
        # Reading the rest of the file
        fileContent = open(fileName,'rb').read()
        pdfFile.setSize(len(fileContent))
        pdfFile.setMD5(hashlib.md5(fileContent).hexdigest())
        pdfFile.setSHA1(hashlib.sha1(fileContent).hexdigest())
        pdfFile.setSHA256(hashlib.sha256(fileContent).hexdigest())
        
        # Getting the number of updates in the file
        while fileContent.find('%%EOF') != -1:
            self.readUntilSymbol(fileContent, '%%EOF')
            self.readUntilEndOfLine(fileContent)
            self.fileParts.append(fileContent[:self.charCounter])
            fileContent = fileContent[self.charCounter:]
            self.charCounter = 0
        else:
            if self.fileParts == []:
                errorMessage = '%%EOF not found'
                if forceMode:
                    pdfFile.addError(errorMessage)
                    self.fileParts.append(fileContent)
                else:
                    sys.exit(errorMessage)
        pdfFile.setUpdates(len(self.fileParts) - 1)
        
        # Getting the body, cross reference table and trailer of each part of the file
        for i in range(len(self.fileParts)):
            bodyOffset = 0
            xrefOffset = 0
            trailerOffset = 0
            eofOffset = 0
            xrefObject = None
            xrefContent = None
            xrefSection = None
            xrefStreamSection = None
            xrefFound = False
            streamTrailer = None
            trailer = None
            trailerFound = False
            pdfIndirectObject = None
            if not pdfFile.isEncrypted():
                encryptDict = None
                encryptDictId = None
            if pdfFile.getFileId() == '':
                fileId = None
            content = self.fileParts[i]
            if i == 0:
                bodyOffset = 0
            else:
                bodyOffset = len(self.fileParts[i-1])
                
            # Getting the content for each section
            bodyContent,xrefContent,trailerContent = self.parsePDFSections(content,forceMode,looseMode)
            if xrefContent != None:    
                xrefOffset = bodyOffset + len(bodyContent)
                trailerOffset = xrefOffset + len(xrefContent)
                bodyContent = bodyContent.strip('\r\n')
                xrefContent = xrefContent.strip('\r\n')
                trailerContent = trailerContent.strip('\r\n')
                trailerFound = True
                xrefFound = True
            else:
                if trailerContent != None:
                    xrefOffset = -1
                    trailerOffset = bodyOffset + len(bodyContent)
                    bodyContent = bodyContent.strip('\r\n')
                    trailerContent = trailerContent.strip('\r\n')    
                else:
                    errorMessage = 'PDF sections not found'
                    if forceMode:
                        pdfFile.addError(errorMessage)
                    else:
                        sys.exit('Error: '+errorMessage+'!!')

                    
            # Converting the body content in PDFObjects
            body = PDFBody()
            rawIndirectObjects = self.getIndirectObjects(bodyContent, looseMode)
            if rawIndirectObjects != []:
                for j in range(len(rawIndirectObjects)):
                    relativeOffset = 0
                    auxContent = str(bodyContent)
                    rawObject = rawIndirectObjects[j][0]
                    objectHeader = rawIndirectObjects[j][1]
                    while True:
                        index = auxContent.find(objectHeader)
                        if index == -1:
                            relativeOffset = index
                            break
                        relativeOffset += index
                        checkHeader = bodyContent[relativeOffset-1:relativeOffset+len(objectHeader)]
                        if not re.match('\d{1,10}'+objectHeader,checkHeader):
                            break
                        else:
                            auxContent = auxContent[index+len(objectHeader):]
                            relativeOffset += len(objectHeader)
                    ret = self.createPDFIndirectObject(rawObject, forceMode, looseMode)
                    if ret[0] != -1:
                        pdfIndirectObject = ret[1]
                        if pdfIndirectObject != None:
                            if relativeOffset == -1:
                                pdfIndirectObject.setOffset(relativeOffset)
                            else:
                                pdfIndirectObject.setOffset(bodyOffset + relativeOffset)
                            ret = body.registerObject(pdfIndirectObject)
                            if ret[0] == -1:
                                pdfFile.addError(ret[1])
                            type = ret[1]
                            pdfObject = pdfIndirectObject.getObject()
                            if pdfObject != None:
                                objectType = pdfObject.getType()
                                if objectType == 'dictionary':
                                    if isFirstBody and not linearizedFound:
                                        if pdfObject.hasElement('/Linearized'):
                                            pdfFile.setLinearized(True)
                                            linearizedFound = True
                                elif objectType == 'stream' and type == '/XRef':
                                    xrefObject = pdfIndirectObject
                                    ret = self.createPDFCrossRefSectionFromStream(pdfIndirectObject)
                                    if ret[0] != -1:
                                        xrefStreamSection = ret[1]    
                            else:
                                if not forceMode:
                                    sys.exit('Error: An error has occurred while parsing an indirect object!!')
                                else:
                                    pdfFile.addError('Object is None')        
                        else:
                            if not forceMode:
                                sys.exit('Error: Bad indirect object!!')
                            else:
                                pdfFile.addError('Indirect object is None')    
                    else:
                        if not forceMode:
                            sys.exit('Error: An error has occurred while parsing an indirect object!!')
                        else:
                            pdfFile.addError('Error parsing object: '+str(objectHeader)+' ('+str(ret[1])+')')
            else:
                pdfFile.addError('No indirect objects found in the body')
            if pdfIndirectObject != None:
                body.setNextOffset(pdfIndirectObject.getOffset())
            ret = body.updateObjects()
            if ret[0] == -1:
                pdfFile.addError(ret[1])
            pdfFile.addBody(body)
            pdfFile.addNumObjects(body.getNumObjects())
            pdfFile.addNumStreams(body.getNumStreams())
            pdfFile.addNumEncodedStreams(body.getNumEncodedStreams())
            pdfFile.addNumDecodingErrors(body.getNumDecodingErrors())
            isFirstBody = False
            
            # Converting the cross reference table content in PDFObjects
            if xrefContent != None:
                ret = self.createPDFCrossRefSection(xrefContent,xrefOffset)
                if ret[0] != -1:
                    xrefSection = ret[1]
            pdfFile.addCrossRefTableSection([xrefSection, xrefStreamSection])
            
            # Converting the trailer content in PDFObjects
            if body.containsXrefStreams():
                ret = self.createPDFTrailerFromStream(xrefObject,trailerContent)
                if ret[0] != -1:
                    streamTrailer = ret[1]
                ret = self.createPDFTrailer(trailerContent, trailerOffset, streamPresent = True)
                if ret[0] != -1:
                    trailer = ret[1]
                if streamTrailer != None and not pdfFile.isEncrypted():
                    encryptDict = streamTrailer.getDictEntry('/Encrypt')
                    if encryptDict != None:
                        pdfFile.setEncrypted(True)
                    elif trailer != None:
                        encryptDict = trailer.getDictEntry('/Encrypt')
                        if encryptDict != None:
                            pdfFile.setEncrypted(True)
                    fileId = streamTrailer.getDictEntry('/ID')
                    if fileId == None and trailer != None:
                        fileId = trailer.getDictEntry('/ID')
            else:
                ret = self.createPDFTrailer(trailerContent, trailerOffset)
                if ret[0] != -1 and not pdfFile.isEncrypted():
                    trailer = ret[1]
                    encryptDict = trailer.getDictEntry('/Encrypt')
                    if encryptDict != None:
                        pdfFile.setEncrypted(True)
                    fileId = trailer.getDictEntry('/ID')
            if pdfFile.getEncryptDict() == None and encryptDict != None:
                objectType = encryptDict.getType()
                if objectType == 'reference':
                    encryptDictId = encryptDict.getId()
                    encryptObject = pdfFile.getObject(encryptDictId,i)
                    if encryptObject != None:
                        objectType = encryptObject.getType()
                        encryptDict = encryptObject
                    else:
                        if i == pdfFile.updates:
                            pdfFile.addError('/Encrypt dictionary not found')
                if objectType == 'dictionary':
                    pdfFile.setEncryptDict([encryptDictId,encryptDict.getElements()])

            if fileId != None and pdfFile.getFileId() == '':
                objectType = fileId.getType()
                if objectType == 'array':
                    fileIdElements = fileId.getElements()
                    if fileIdElements != None and fileIdElements != []:
                        if fileIdElements[0] != None:
                            fileId = fileIdElements[0].getValue()
                            pdfFile.setFileId(fileId)
                        elif fileIdElements[1] != None:
                            fileId = fileIdElements[1].getValue()
                            pdfFile.setFileId(fileId)
            pdfFile.addTrailer([trailer, streamTrailer])
        if pdfFile.isEncrypted() and pdfFile.getEncryptDict() != None:
            ret = pdfFile.decrypt()
            if ret[0] == -1:
                pdfFile.addError(ret[1])
        return (0,pdfFile)

    def parsePDFSections(self, content, forceMode = False, looseMode = False):
        '''
            Method to parse the different sections of a version of a PDF document.
            @param content The raw content of the version of the PDF document.
            @param forceMode Boolean to specify if ignore errors or not. Default value: False.
            @param looseMode Boolean to set the loose mode when parsing objects. Default value: False.
            @return An array with the different sections found: body, trailer and cross reference table
        '''
        threeSections = False
        bodyContent = None
        xrefContent = None
        trailerContent = None
        
        global pdfFile
        indexTrailer = content.find('trailer')
        if indexTrailer != -1:
            restContent = content[:indexTrailer]
            auxTrailer = content[indexTrailer:]
            indexEOF = auxTrailer.find('%%EOF')
            if indexEOF == -1:
                trailerContent = auxTrailer
            else:
                trailerContent = auxTrailer[:indexEOF+5]
            indexXref = restContent.find('xref')
            if indexXref != -1:
                bodyContent = restContent[:indexXref]
                xrefContent = restContent[indexXref:]
            else:
                bodyContent = restContent
                if forceMode:
                    pdfFile.addError('Xref section not found')
            return [bodyContent,xrefContent,trailerContent]                
                
        indexTrailer = content.find('startxref')
        if indexTrailer != -1:
            restContent = content[:indexTrailer]
            auxTrailer = content[indexTrailer:]
            indexEOF = auxTrailer.find('%%EOF')
            if indexEOF == -1:
                trailerContent = auxTrailer
            else:
                trailerContent = auxTrailer[:indexEOF+5]
            bodyContent = restContent
            return [bodyContent,xrefContent,trailerContent]
        
        return [content,xrefContent,trailerContent]
    
    def createPDFIndirectObject (self, rawIndirectObject, forceMode = False, looseMode = False) :
        '''
            Create a PDFIndirectObject instance from the raw content of the PDF file
            @param rawIndirectObject string with the raw content of the PDF body.
            @param forceMode specifies if the parsing process should ignore errors or not (boolean).
            @param looseMode specifies if the parsing process should search for the endobj tag or not (boolean).
            @return A tuple (status,statusContent), where statusContent is the PDFIndirectObject in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        try:
            self.charCounter = 0
            pdfIndirectObject = PDFIndirectObject()
            ret,id = self.readUntilNotRegularChar(rawIndirectObject)
            pdfIndirectObject.setId(int(id))
            ret,genNum = self.readUntilNotRegularChar(rawIndirectObject)
            pdfIndirectObject.setGenerationNumber(int(genNum))
            ret = self.readSymbol(rawIndirectObject, 'obj')
            if ret[0] == -1:
                return ret
            rawObject = rawIndirectObject[self.charCounter:]
            ret = self.readObject(rawObject, forceMode = forceMode, looseMode = looseMode)
            if ret[0] == -1:
                return ret
            object = ret[1]
            pdfIndirectObject.setObject(object)
            ret = self.readSymbol(rawIndirectObject, 'endobj', False)
            pdfIndirectObject.setSize(self.charCounter)
        except:
            errorMessage = 'Unspecified parsing error'
            pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        pdfFile.setMaxObjectId(id)
        return (0,pdfIndirectObject)

    def createPDFArray(self, rawContent):
        '''
            Create a PDFArray instance from the raw content of the PDF file
            @param rawContent string with the raw content of the PDF body.
            @return A tuple (status,statusContent), where statusContent is the PDFArray in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        realCounter = self.charCounter
        self.charCounter = 0
        elements = []
        ret = self.readObject(rawContent)
        if ret[0] == -1:
            if ret[1] != 'Empty content reading object':
                if isForceMode:
                    pdfFile.addError(ret[1])
                    pdfObject = None
                else:
                    return ret
            else:
                pdfObject = None
        else:
            pdfObject = ret[1]
        while pdfObject != None:
            elements.append(pdfObject)
            ret = self.readObject(rawContent[self.charCounter:])
            if ret[0] == -1:
                if ret[1] != 'Empty content reading object':
                    if isForceMode:
                        pdfFile.addError(ret[1])
                        pdfObject = None
                    else:
                        return ret
                else:
                    pdfObject = None
            else:
                pdfObject = ret[1]
        try:
            pdfArray = PDFArray(rawContent, elements)
        except Exception,e:
            errorMessage = 'Error creating PDFArray'
            if e.message != '':
                errorMessage += ': '+e.message
            return (-1, errorMessage)
        self.charCounter = realCounter
        return (0,pdfArray)
        
    def createPDFDictionary(self, rawContent):
        '''
            Create a PDFDictionary instance from the raw content of the PDF file
            @param rawContent string with the raw content of the PDF body.
            @return A tuple (status,statusContent), where statusContent is the PDFDictionary in case status = 0 or an error in case status = -1
        '''
        realCounter = self.charCounter
        self.charCounter = 0
        elements = {}
        rawNames = {}
        ret = self.readObject(rawContent[self.charCounter:], 'name')
        if ret[0] == -1:
            if ret[1] != 'Empty content reading object':
                if isForceMode:
                    pdfFile.addError(ret[1])
                    name = None
                else:
                    return ret
            else:
                name = None
        else:
            name = ret[1]
        while name != None:
            key = name.getValue()
            rawNames[key] = name
            rawValue = rawContent[self.charCounter:]
            ret = self.readObject(rawValue)
            if ret[0] == -1:
                if isForceMode:
                    pdfFile.addError('Bad object for '+str(key)+' key')
                    ret = self.readUntilSymbol(rawContent, '/')
                    if ret[0] == -1:
                        elements[key] = PDFString(rawValue)
                    else:
                        elements[key] = PDFString(ret[1])
                    self.readSpaces(rawContent)
                else:
                    return (-1,'Bad object for '+str(key)+' key')
            else:
                value = ret[1]
                elements[key] = value
            ret = self.readObject(rawContent[self.charCounter:], 'name')
            if ret[0] == -1:
                if ret[1] != 'Empty content reading object':
                    if isForceMode:
                        pdfFile.addError(ret[1])
                        name = None
                    else:
                        return ret
                else:
                    name = None
            else:
                name = ret[1]
                if name != None and name.getType() != 'name':
                    errorMessage = 'Name object not found in dictionary key'
                    if isForceMode:
                        pdfFile.addError(errorMessage)
                        name = None
                    else:
                        return (-1, errorMessage)
        try:
            pdfDictionary = PDFDictionary(rawContent, elements, rawNames)
        except Exception,e:
            errorMessage = 'Error creating PDFDictionary'
            if e.message != '':
                errorMessage += ': '+e.message
            return (-1, errorMessage)
        self.charCounter = realCounter
        return (0,pdfDictionary)

    def createPDFStream(self, dict, stream):
        '''
            Create a PDFStream or PDFObjectStream instance from the raw content of the PDF file
            @param dict Raw content of the dictionary object.
            @param stream Raw content of the stream.
            @return A tuple (status,statusContent), where statusContent is the PDFStream or PDFObjectStream in case status = 0 or an error in case status = -1
        '''
        realCounter = self.charCounter
        self.charCounter = 0
        elements = {}
        rawNames = {}
        ret = self.readObject(dict[self.charCounter:], 'name')
        if ret[0] == -1:
            if ret[1] != 'Empty content reading object':
                if isForceMode:
                    pdfFile.addError(ret[1])
                    name = None
                else:
                    return ret
            else:
                name = None
        else:
            name = ret[1]    
        while name != None:
            key = name.getValue()
            rawNames[key] = name
            ret = self.readObject(dict[self.charCounter:])
            if ret[0] == -1:
                if ret[1] != 'Empty content reading object':
                    if isForceMode:
                        pdfFile.addError(ret[1])
                        value = None
                    else:
                        return ret
                else:
                    value = None
            else:
                value = ret[1]
            elements[key] = value
            ret = self.readObject(dict[self.charCounter:], 'name')
            if ret[0] == -1:
                if ret[1] != 'Empty content reading object':
                    if isForceMode:
                        pdfFile.addError(ret[1])
                        name = None
                    else:
                        return ret
                else:
                    name = None
            else:
                name = ret[1]
        if elements.has_key('/Type') and elements['/Type'].getValue() == '/ObjStm':
            try:
                pdfStream = PDFObjectStream(dict, stream, elements, rawNames, {})
            except Exception,e:
                errorMessage = 'Error creating PDFObjectStream'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        else:
            try:
                pdfStream = PDFStream(dict, stream, elements, rawNames)
            except Exception,e:
                errorMessage = 'Error creating PDFStream'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        self.charCounter = realCounter
        return (0,pdfStream)

    def createPDFCrossRefSection (self, rawContent, offset):
        '''
            Create a PDFCrossRefSection instance from the raw content of the PDF file
            @param rawContent String with the raw content of the PDF body (string)
            @param offset Offset of the cross reference section in the PDF file (int)
            @return A tuple (status,statusContent), where statusContent is the PDFCrossRefSection in case status = 0 or an error in case status = -1
        '''
        global isForceMode,pdfFile
        if not isinstance(rawContent,str):
            return (-1,'Empty xref content')
        entries = []
        auxOffset = 0
        subSectionSize = 0
        self.charCounter = 0
        pdfCrossRefSection = PDFCrossRefSection()
        pdfCrossRefSection.setOffset(offset)
        pdfCrossRefSection.setSize(len(rawContent))
        pdfCrossRefSubSection = None
        beginSubSectionRE = re.compile('(\d{1,10})\s(\d{1,10})\s*$')
        entryRE = re.compile('(\d{10})\s(\d{5})\s([nf])')
        ret = self.readSymbol(rawContent, 'xref')
        if ret[0] == -1:
            return ret
        auxOffset += self.charCounter
        lines = self.getLines(rawContent[self.charCounter:])
        if lines == []:
            if isForceMode:
                pdfCrossRefSubSection = PDFCrossRefSubSection(0, offset = -1)
                pdfFile.addError('No entries in xref section')
            else:
                return (-1,'Error: No entries in xref section!!')
        else:
            for line in lines:
                match = re.findall(beginSubSectionRE,line)
                if match != []:
                    if pdfCrossRefSubSection != None:        
                        pdfCrossRefSubSection.setSize(subSectionSize)
                        pdfCrossRefSection.addSubsection(pdfCrossRefSubSection)
                        pdfCrossRefSubSection.setEntries(entries)
                        subSectionSize = 0
                        entries = []
                    try:
                        pdfCrossRefSubSection = PDFCrossRefSubSection(match[0][0],match[0][1],offset = auxOffset)
                    except:
                        return (-1,'Error creating PDFCrossRefSubSection')
                else:
                    match = re.findall(entryRE,line)
                    if match != []:
                        try:
                            pdfCrossRefEntry = PDFCrossRefEntry(match[0][0],match[0][1],match[0][2], offset = auxOffset)
                        except:
                            return (-1,'Error creating PDFCrossRefEntry')
                        entries.append(pdfCrossRefEntry)
                    else:
                        #TODO: comments in line or spaces/\n\r...?
                        if isForceMode:
                            if pdfCrossRefSubSection != None:
                                pdfCrossRefSubSection.addError('Bad format for cross reference entry: '+line)
                            else:
                                pdfCrossRefSubSection = PDFCrossRefSubSection(0, offset = -1)
                                pdfFile.addError('Bad xref section')
                        else:
                            return (-1,'Bad format for cross reference entry')
                auxOffset += len(line)
                subSectionSize += len(line)
        pdfCrossRefSubSection.setSize(subSectionSize)
        pdfCrossRefSection.addSubsection(pdfCrossRefSubSection)
        pdfCrossRefSubSection.setEntries(entries)
        return (0,pdfCrossRefSection)

    def createPDFCrossRefSectionFromStream (self, objectStream):
        '''
            Create a PDFCrossRefSection instance from the raw content of the PDF file
            @param objectStream Object stream object (PDFIndirectObject).
            @return A tuple (status,statusContent), where statusContent is the PDFCrossRefSection in case status = 0 or an error in case status = -1
        '''
        index = 0
        firstEntry = 0
        entries = []
        numObjects = 0
        numSubsections = 1
        bytesPerField = [1,2,1]
        entrySize = 4
        subsectionIndexes = []
        if objectStream != None:
            pdfCrossRefSection = PDFCrossRefSection()
            pdfCrossRefSection.setXrefStreamObject(objectStream.getId())
            xrefObject = objectStream.getObject()
            if xrefObject != None:
                if xrefObject.hasElement('/Size'):
                    sizeObject = xrefObject.getElementByName('/Size')
                    if sizeObject != None and sizeObject.getType() == 'integer':
                        numObjects = sizeObject.getRawValue()
                        subsectionIndexes = [0,numObjects]
                    else:
                        errorMessage = 'Bad object type for /Size element'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                else:
                    errorMessage = 'Element /Size not found'
                    if isForceMode:
                        pdfCrossRefSection.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
                    
                if xrefObject.hasElement('/W'):
                    bytesPerFieldObject = xrefObject.getElementByName('/W')
                    if bytesPerFieldObject.getType() == 'array':
                        bytesPerField = bytesPerFieldObject.getElementRawValues()
                        if len(bytesPerField) != 3:
                            errorMessage = 'Bad content of /W element'
                            if isForceMode:
                                pdfCrossRefSection.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                        else:
                            entrySize = 0
                            for num in bytesPerField:
                                entrySize += num
                    else:
                        errorMessage = 'Bad object type for /W element'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                else:
                    errorMessage = 'Element /W not found'
                    if isForceMode:
                        pdfCrossRefSection.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
                    
                if xrefObject.hasElement('/Index'):
                    subsectionIndexesObject = xrefObject.getElementByName('/Index')
                    if subsectionIndexesObject.getType() == 'array':
                        subsectionIndexes = subsectionIndexesObject.getElementRawValues()
                        if len(subsectionIndexes) % 2 != 0:
                            errorMessage = 'Bad content of /Index element'
                            if isForceMode:
                                pdfCrossRefSection.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                        else:
                            numSubsections = len(subsectionIndexes) / 2
                    else:
                        errorMessage = 'Bad object type for /Index element'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
        
                pdfCrossRefSection.setBytesPerField(bytesPerField)
                stream = xrefObject.getStream()
                for i in range(0,len(stream),entrySize):
                    entryBytes = stream[i:i+entrySize]
                    try:
                        if bytesPerField[0] == 0:
                            f1 = 1
                        else:
                            f1 = int(entryBytes[:bytesPerField[0]].encode('hex'),16)
                        if bytesPerField[1] == 0:
                            f2 = 0
                        else:
                            f2 = int(entryBytes[bytesPerField[0]:bytesPerField[0]+bytesPerField[1]].encode('hex'),16)
                        if bytesPerField[2] == 0:
                            f3 = 0
                        else:
                            f3 = int(entryBytes[bytesPerField[0]+bytesPerField[1]:].encode('hex'),16)
                    except:
                        errorMessage = 'Error in hexadecimal conversion'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                    try:
                        pdfCrossRefEntry = PDFCrossRefEntry(f2,f3,f1)
                    except:
                        errorMessage = 'Error creating PDFCrossRefEntry'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                    entries.append(pdfCrossRefEntry)
                for i in range(numSubsections):
                    firstObject = subsectionIndexes[index]
                    numObjectsInSubsection = subsectionIndexes[index+1]
                    try:
                        pdfCrossRefSubSection = PDFCrossRefSubSection(firstObject,numObjectsInSubsection)
                    except:
                        errorMessage = 'Error creating PDFCrossRefSubSection'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                    pdfCrossRefSubSection.setEntries(entries[firstEntry:firstEntry+numObjectsInSubsection])
                    pdfCrossRefSection.addSubsection(pdfCrossRefSubSection)
                    firstentry = numObjectsInSubsection
                    index += 2
                return (0,pdfCrossRefSection)
            else:
                return (-1,'The object stream is None')
        else:
            return (-1,'The indirect object stream is None')

    def createPDFTrailer (self, rawContent, offset, streamPresent = False) :
        '''
            Create a PDFTrailer instance from the raw content of the PDF file
            @param rawContent String with the raw content of the PDF body (string)
            @param offset Offset of the trailer in the PDF file (int)
            @param streamPresent It specifies if an object stream exists in the PDF body
            @return A tuple (status,statusContent), where statusContent is the PDFTrailer in case status = 0 or an error in case status = -1
        '''
        global pdfFile,isForceMode
        trailer = None
        self.charCounter = 0
        if not isinstance(rawContent,str):
            return (-1,'Empty trailer content')
        self.readSymbol(rawContent, 'trailer')    
        ret = self.readObject(rawContent[self.charCounter:],'dictionary')
        if ret[0] == -1:
            dict = PDFDictionary('')
            dict.addError('Error creating the trailer dictionary')
        else:
            dict = ret[1]
        ret = self.readSymbol(rawContent, 'startxref')
        if ret[0] == -1:
            try:
                trailer = PDFTrailer(dict, streamPresent = streamPresent)
            except Exception,e:
                errorMessage = 'Error creating PDFTrailer'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        else:
            ret = self.readUntilEndOfLine(rawContent)
            if ret[0] == -1:
                if isForceMode:
                    lastXrefSection = -1
                    pdfFile.addError('EOL not found while looking for the last cross reference section')
                else:
                    return (-1,'EOL not found while looking for the last cross reference section')
            else:
                lastXrefSection = ret[1]
            try:
                trailer = PDFTrailer(dict, lastXrefSection, streamPresent = streamPresent)
            except Exception,e:
                errorMessage = 'Error creating PDFTrailer'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        trailer.setOffset(offset)
        eofOffset = rawContent.find('%%EOF')
        if eofOffset == -1:
            trailer.setEOFOffset(eofOffset)
            trailer.setSize(len(rawContent))
        else:
            trailer.setEOFOffset(offset+eofOffset)
            trailer.setSize(eofOffset)
        return (0,trailer)
    
    def createPDFTrailerFromStream (self, indirectObject, rawContent) :
        '''
            Create a PDFTrailer instance from the raw content of the PDF file
            @param indirectObject Object stream object (PDFIndirectObject).
            @param rawContent String with the raw content of the PDF body (string)
            @return A tuple (status,statusContent), where statusContent is the PDFTrailer in case status = 0 or an error in case status = -1
        '''
        trailer = None
        self.charCounter = 0
        trailerElements = ['/Size','/Prev','/Root','/Encrypt','/Info','/ID']
        dict = {}
        if indirectObject != None:
            xrefStreamObject = indirectObject.getObject()
            if xrefStreamObject != None:
                for element in trailerElements:
                    if xrefStreamObject.hasElement(element):
                        dict[element] = xrefStreamObject.getElementByName(element)
                try:
                    dict = PDFDictionary('',dict)
                except Exception,e:
                    if isForceMode:
                        dict = None
                    else:
                        errorMessage = 'Error creating PDFDictionary'
                        if e.message != '':
                            errorMessage += ': '+e.message
                        return (-1, errorMessage)
                if not isinstance(rawContent,str):
                    if isForceMode:
                        lastXrefSection = -1
                    else:
                        return (-1,'Empty trailer content')
                else:
                    ret = self.readUntilSymbol(rawContent, 'startxref')
                    if ret[0] == -1 and not isForceMode:
                        return ret
                    ret = self.readSymbol(rawContent, 'startxref')
                    if ret[0] == -1 and not isForceMode:
                        return ret
                    ret = self.readUntilEndOfLine(rawContent)
                    if ret[0] == -1:
                        if not isForceMode:
                            return ret
                        lastXrefSection = -1
                    else:
                        lastXrefSection = ret[1]
                try:
                    trailer = PDFTrailer(dict, lastXrefSection)
                except Exception,e:
                    errorMessage = 'Error creating PDFTrailer'
                    if e.message != '':
                        errorMessage += ': '+e.message
                    return (-1, errorMessage)
                trailer.setXrefStreamObject(indirectObject.getId())
            else:
                return (-1,'Object stream is None')
        else:
            return (-1,'Indirect object stream is None')
        return (0,trailer)

    def getIndirectObjects(self, content, looseMode = False):
        '''
            This function returns an array of raw indirect objects of the PDF file given the raw body.
            @param content: string with the raw content of the PDF body.
            @param looseMode: boolean specifies if the parsing process should search for the endobj tag or not.
            @return matchingObjects: array of tuples (object_content,object_header).
        '''
        global pdfFile
        matchingObjects = []
        if not isinstance(content,str):
            return matchingObjects
        if not looseMode:
            regExp = re.compile('((\d{1,10}\s\d{1,10}\sobj).*?endobj)',re.DOTALL)
            matchingObjects = regExp.findall(content)
        else:
            regExp = re.compile('((\d{1,10}\s\d{1,10}\sobj).*?)\s\d{1,10}\s\d{1,10}\sobj',re.DOTALL)
            matchingObjectsAux = regExp.findall(content)
            while matchingObjectsAux != []:
                if matchingObjectsAux[0] != []:
                    objectBody = matchingObjectsAux[0][0]
                    matchingObjects.append(matchingObjectsAux[0])
                    content = content[content.find(objectBody)+len(objectBody):]
                    matchingObjectsAux = regExp.findall(content)
                else:
                    matchingObjectsAux = []
            lastObject = re.findall('(\d{1,5}\s\d{1,5}\sobj)',content,re.DOTALL)
            if lastObject != []:
                content = content[content.find(lastObject[0]):]
                matchingObjects.append((content,lastObject[0]))
        return matchingObjects
        
    def getLines(self, content):
        '''
            Simple function to return the lines separated by end of line characters
            @param content
            @return List with the lines, without end of line characters
        '''
        lines = []
        i = 0
        while i < len(content):
            if content[i] == '\r':
                lines.append(content[:i])
                if content[i+1] == '\n':
                    i += 1
                content = content[i+1:]
                i = 0
            elif content[i] == '\n':
                lines.append(content[:i])
                content = content[i+1:]
                i = 0
            i += 1
        if i > 0:
            lines.append(content)
        return lines
    
    def readObject(self, content, objectType = None, forceMode = False, looseMode = False):
        '''
            Method to parse the raw body of the PDF file and obtain PDFObject instances
            @param content
            @param objectType
            @param forceMode
            @param looseMode
            @return A tuple (status,statusContent), where statusContent is a PDFObject instance in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if len(content) == 0 or content[:6] == 'endobj':
            return (-1,'Empty content reading object')
        pdfObject = None
        oldCounter = self.charCounter
        self.charCounter = 0
        if objectType != None:
            objectsTypeArray = [self.delimiters[i][2] for i in range(len(self.delimiters))]
            index = objectsTypeArray.index(objectType)
            if index != -1:
                delimiters = [self.delimiters[index]]
            else:
                if isForceMode:
                    pdfFile.addError('Unknown object type while parsing object')
                    return (-1,'Unknown object type')
                else:
                    sys.exit('Error: Unknown object type!!')
        else:
            delimiters = self.delimiters
        for delim in delimiters:
            ret = self.readSymbol(content, delim[0])
            if ret[0] != -1:
                if delim[2] == 'dictionary':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] == -1:
                        dictContent = ''
                    else:
                        dictContent = ret[1]
                    nonDictContent = content[self.charCounter:]
                    streamFound = re.findall('[>\s]stream', nonDictContent)
                    if streamFound:
                        ret = self.readUntilSymbol(content, 'stream')
                        if ret[0] == -1:
                            return ret
                        auxDict = ret[1]
                        self.readSymbol(content, 'stream', False)
                        self.readUntilEndOfLine(content)
                        self.readSymbol(content, '\r', False)
                        self.readSymbol(content, '\n', False)
                        ret = self.readUntilSymbol(content, 'endstream')
                        if ret[0] == -1:
                            stream = content[self.charCounter:]
                        else:
                            stream = ret[1]
                            self.readSymbol(content, 'endstream')
                        ret = self.createPDFStream(dictContent, stream)
                        if ret[0] == -1:
                            return ret
                        pdfObject = ret[1]
                        break
                    else:
                        if ret[0] != -1:
                            self.readSymbol(content, delim[1])
                            ret = self.createPDFDictionary(dictContent)
                            if ret[0] == -1:
                                return ret
                            pdfObject = ret[1]
                        else:
                            pdfObject = PDFDictionary(content)
                            pdfObject.addError('Closing delimiter not found in dictionary object')
                        break
                elif delim[2] == 'string':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] != -1:
                        stringContent = ret[1]
                        self.readSymbol(content, delim[1])
                        pdfObject = PDFString(stringContent)
                    else:
                        pdfObject = PDFString(content)
                        pdfObject.addError('Closing delimiter not found in string object')
                    break
                elif delim[2] == 'hexadecimal':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] != -1:
                        hexContent = ret[1]
                        self.readSymbol(content, delim[1])
                        pdfObject = PDFHexString(hexContent)
                    else:
                        pdfObject = PDFHexString(content)
                        pdfObject.addError('Closing delimiter not found in hexadecimal object')
                    break
                elif delim[2] == 'array':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] != -1:
                        arrayContent = ret[1]
                        self.readSymbol(content, delim[1])
                        ret = self.createPDFArray(arrayContent)
                        if ret[0] == -1:
                            return ret
                        pdfObject = ret[1]
                    else:
                        pdfObject = PDFArray(content)
                        pdfObject.addError('Closing delimiter not found in array object')
                    break
                elif delim[2] == 'name':
                    ret,raw = self.readUntilNotRegularChar(content)
                    pdfObject = PDFName(raw)
                    break
                elif delim[2] == 'comment':
                    ret = self.readUntilEndOfLine(content)
                    if ret[0] == 0:
                        self.comments.append(ret[1])
                        self.readSpaces(content)
                        pdfObject = self.readObject(content[self.charCounter:],objectType)
                    else:
                        return ret
                    break
        else:
            if content[0] == 't' or content[0] == 'f':
                ret,raw = self.readUntilNotRegularChar(content)
                pdfObject = PDFBool(raw)
            elif content[0] == 'n':
                ret,raw = self.readUntilNotRegularChar(content)
                pdfObject = PDFNull(raw)
            elif re.findall('^(\d{1,10}\s{1,3}\d{1,10}\s{1,3}R)', content, re.DOTALL) != []:
                ret,id = self.readUntilNotRegularChar(content)
                ret,genNumber = self.readUntilNotRegularChar(content)
                ret = self.readSymbol(content, 'R')
                if ret[0] == -1:
                    return ret
                pdfObject = PDFReference(id, genNumber)
            elif re.findall('^([-+]?\.?\d{1,15}\.?\d{0,15})', content, re.DOTALL) != []:
                ret,num = self.readUntilNotRegularChar(content)
                pdfObject = PDFNum(num)
            else:
                self.charCounter += oldCounter
                return (-1,'Object not found')
        self.charCounter += oldCounter
        return (0,pdfObject)

    def readSpaces(self, string):
        '''
            Reads characters until all spaces chars have been read
            @param string 
            @return A tuple (status,statusContent), where statusContent is the number of characters read in case status = 0 or an error in case status = -1
        '''
        if not isinstance(string,str):
            return (-1,'Bad string')
        spacesCounter = self.charCounter
        for i in range(self.charCounter,len(string)):
            if string[i] not in spacesChars:
                break
            self.charCounter += 1
        spacesCounter -= self.charCounter
        return (0,spacesCounter)

    def readSymbol(self, string, symbol, deleteSpaces = True):
        '''
            Reads a given symbol from the string, removing comments and spaces (if specified)
            @param string
            @param symbol
            @param deleteSpaces
            @return A tuple (status,statusContent), where statusContent is the number of characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if not isinstance(string,str):
            return (-1,'Bad string')
        oldCharCounter = self.charCounter
        if self.charCounter > len(string)-1:
            errorMessage = 'EOF while looking for symbol "'+symbol+'"'
            pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        while string[self.charCounter] == '%':
            ret = self.readUntilEndOfLine(string)
            if ret[0] == -1:
                return ret
            self.comments.append(ret[1])
            self.readSpaces(string)
        symbolToRead = string[self.charCounter:self.charCounter+len(symbol)]
        if symbolToRead != symbol:
            errorMessage = 'Symbol "'+symbol+'" not found while parsing'
            #pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        self.charCounter += len(symbol)
        if deleteSpaces:
            self.readSpaces(string)
        return (0,self.charCounter - oldCharCounter)

    def readUntilClosingDelim(self, content, delim):
        '''
            Method that reads characters until it finds the closing delimiter
            @param content
            @param delim
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        output = ''
        if not isinstance(content,str):
            return (-1,'Bad string')
        newContent = content[self.charCounter:]
        numOpeningDelims = newContent.count(delim[0]) + 1
        numClosingDelims = newContent.count(delim[1])
        if numClosingDelims == 0:
            errorMessage = 'No closing delimiter found'
            pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        elif numClosingDelims == 1:
            index = newContent.rfind(delim[1])
            self.charCounter += index
            return (0,newContent[:index])
        else:
            indexChar = 0
            prevChar = ''
            while indexChar != len(newContent):
                char = newContent[indexChar]
                if indexChar == len(newContent) - 1:
                    nextChar = ''
                else:
                    nextChar = newContent[indexChar+1]
                if char == delim[1] or (char + nextChar) == delim[1]:
                    if char != ')' or indexChar == 0 or newContent[indexChar-1] != '\\':
                        return (0,output)
                    else:
                        output += char
                        indexChar += 1
                        self.charCounter += 1
                elif (char == '(' and prevChar != '\\') or (char in ['[','<'] and delim[0] != '('):
                    if (char + nextChar) != '<<':
                        delimIndex = delimiterChars.index(char)
                        self.charCounter += 1
                        ret = self.readUntilClosingDelim(content, self.delimiters[delimIndex])
                        if ret[0] != -1:
                            tempObject = char + ret[1]
                        else:
                            return ret
                    else:
                        delimIndex = delimiterChars.index(char + nextChar)
                        self.charCounter += 2
                        ret = self.readUntilClosingDelim(content, self.delimiters[delimIndex])
                        if ret[0] != -1:
                            tempObject = char + nextChar + ret[1]
                        else:
                            return ret
                    ret = self.readSymbol(content, self.delimiters[delimIndex][1], False)
                    if ret[0] != -1:
                        tempObject += self.delimiters[delimIndex][1]
                    else:
                        return ret
                    indexChar += len(tempObject)
                    output += tempObject
                else:
                    indexChar += 1
                    self.charCounter += 1
                    output += char
                    prevChar = char            
            else:
                errorMessage = 'No closing delimiter found'
                pdfFile.addError(errorMessage)
                return (-1, errorMessage)
    
    def readUntilEndOfLine(self, content):
        '''
            This function reads characters until the end of line
            @param content
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if not isinstance(content,str):
            return (-1,'Bad string')
        errorMessage = []
        oldCharCounter = self.charCounter
        tmpContent = content[self.charCounter:]
        for char in tmpContent:
            if char == '\r' or char == '\n':
                return (0,content[oldCharCounter:self.charCounter])
            self.charCounter += 1
        else:
            errorMessage = 'EOL not found'
            pdfFile.addError(errorMessage)
            return (-1, errorMessage)

    def readUntilLastSymbol(self, string, symbol):
        '''
            Method that reads characters until it finds the last appearance of 'symbol'
            @param string
            @param symbol
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if not isinstance(string,str):
            return (-1,'Bad string')
        newString = string[self.charCounter:]
        index = newString.rfind(symbol)
        if index == -1:
            errorMessage = 'Symbol "'+symbol+'" not found'
            pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        self.charCounter += index
        return (0,newString[:index])
            
    def readUntilNotRegularChar(self, string):
        '''
            Reads the regular chars of the string until it reachs a non-regular char. Then it removes spaces chars.
            @param string 
            @return A tuple (status,statusContent), where statusContent is the number of characters read in case status = 0 or an error in case status = -1
        '''
        readChars = ''
        if not isinstance(string,str):
            return (-1,'Bad string')
        notRegChars = spacesChars + delimiterChars
        for i in range(self.charCounter,len(string)):
            if string[i] in notRegChars:
                self.readSpaces(string)
                break
            readChars += string[i]
            self.charCounter += 1
        return (0,readChars)
            
    def readUntilSymbol(self, string, symbol):
        '''
            Method that reads characters until it finds the first appearance of 'symbol'
            @param string
            @param symbol
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if not isinstance(string,str):
            return (-1,'Bad string')
        newString = string[self.charCounter:]
        index = newString.find(symbol)
        if index == -1:
            errorMessage = 'Symbol "'+symbol+'" not found'
            return (-1, errorMessage)
        self.charCounter += index
        return (0,newString[:index])
