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
    Module to manage cryptographic operations with PDF files
'''    

import hashlib,struct,random,warnings,aes
from itertools import cycle, izip
warnings.filterwarnings("ignore")

paddingString = '\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A'

def computeEncryptionKey(password, dictOwnerPass, dictUserPass, dictOE, dictUE, fileID, pElement, dictKeyLength = 128, revision = 3, encryptMetadata = False, passwordType = None):
    '''
        Compute an encryption key to encrypt/decrypt the PDF file
        
        @param password: The password entered by the user
        @param dictOwnerPass: The owner password from the standard security handler dictionary
        @param dictUserPass: The user password from the standard security handler dictionary
        @param dictOE: The owner encrypted string from the standard security handler dictionary
        @param dictUE:The user encrypted string from the standard security handler dictionary
        @param fileID: The /ID element in the trailer dictionary of the PDF file
        @param pElement: The /P element of the Encryption dictionary
        @param dictKeyLength: The length of the key
        @param revision: The algorithm revision
        @param encryptMetadata: A boolean extracted from the standard security handler dictionary to specify if it's necessary to encrypt the document metadata or not
        @param passwordType: It specifies the given password type. It can be 'USER', 'OWNER' or None.
        @return: A tuple (status,statusContent), where statusContent is the encryption key in case status = 0 or an error message in case status = -1
    '''
    if revision != 5:
        keyLength = dictKeyLength/8
        lenPass = len(password)
        if lenPass > 32:
            password = password[:32]
        elif lenPass < 32:
            password += paddingString[:32-lenPass]
        md5input = password + dictOwnerPass + struct.pack('<I',abs(int(pElement))) + fileID
        if revision > 3 and not encryptMetadata:
            md5input += '\xFF'*4
        key = hashlib.md5(md5input).digest()
        if revision > 2:
            counter = 0
            while counter < 50:
                key = hashlib.md5(key[:keyLength]).digest()
                counter += 1
            key = key[:keyLength]
        elif revision == 2:
            key = key[:5]
        return (0, key)
    else:
        if passwordType == 'USER':
            password = password.encode('utf-8')[:127]
            kSalt = dictUserPass[40:48]
            intermediateKey = hashlib.sha256(password + kSalt).digest()
            ret = aes.decryptData('\0'*16+dictUE, intermediateKey)
        elif passwordType == 'OWNER':
            password = password.encode('utf-8')[:127]
            kSalt = dictOwnerPass[40:48]
            intermediateKey = hashlib.sha256(password + kSalt + dictUserPass).digest()
            ret = aes.decryptData('\0'*16+dictOE, intermediateKey)
        return ret

def computeObjectKey(id, generationNum, encryptionKey, keyLengthBytes, algorithm = 'RC4'):
    '''
        Compute the key necessary to encrypt each object, depending on the id and generation number. Only necessary with /V < 5.
        
        @param id: The object id
        @param generationNum: The generation number of the object
        @param encryptionKey: The encryption key
        @param keyLengthBytes: The length of the encryption key in bytes
        @param algorithm: The algorithm used in the encryption/decryption process
        @return: The computed key in string format
    '''    
    key = encryptionKey + struct.pack('<i',id)[:3] + struct.pack('<i',generationNum)[:2]
    if algorithm == 'AES':
        key += '\x73\x41\x6C\x54' # sAlT
    key = hashlib.md5(key).digest()
    if keyLengthBytes+5 < 16:
        key = key[:keyLengthBytes+5]
    else:
        key = key[:16]
    # AES: block size = 16 bytes, initialization vector (16 bytes), random, first bytes encrypted string
    return key

def computeOwnerPass(ownerPassString, userPassString, keyLength = 128, revision = 3):
    '''
        Compute the owner password necessary to compute the encryption key of the PDF file
        
        @param ownerPassString: The owner password entered by the user
        @param userPassString: The user password entered by the user
        @param keyLength: The length of the key
        @param revision: The algorithm revision
        @return: The computed password in string format
    '''
    # TODO: revision 5
    keyLength = keyLength/8
    lenPass = len(ownerPassString)
    if lenPass > 32:
        ownerPassString = ownerPassString[:32]
    elif lenPass < 32:
        ownerPassString += paddingString[:32-lenPass]
    rc4Key = hashlib.md5(ownerPassString).digest()
    if revision > 2:
        counter = 0
        while counter < 50:
            rc4Key = hashlib.md5(rc4Key).digest()
            counter += 1
    rc4Key = rc4Key[:keyLength]
    lenPass = len(userPassString)
    if lenPass > 32:
        userPassString = userPassString[:32]
    elif lenPass < 32:
        userPassString += paddingString[:32-lenPass]
    ownerPass = RC4(userPassString,rc4Key)
    if revision > 2:
        counter = 1
        while counter <= 19:
            newKey = ''
            for i in range(len(rc4Key)):
                newKey += chr(ord(rc4Key[i]) ^ counter)
            ownerPass = RC4(ownerPass,newKey)
            counter += 1
    return ownerPass

def computeUserPass(userPassString, dictO, fileID, pElement, keyLength = 128, revision = 3, encryptMetadata = False):
    '''
        Compute the user password of the PDF file
        
        @param userPassString: The user password entered by the user
        @param ownerPass: The computed owner password
        @param fileID: The /ID element in the trailer dictionary of the PDF file
        @param pElement: The /P element of the /Encryption dictionary
        @param keyLength: The length of the key
        @param revision: The algorithm revision
        @param encryptMetadata: A boolean extracted from the standard security handler dictionary to specify if it's necessary to encrypt the document metadata or not
        @return: A tuple (status,statusContent), where statusContent is the computed password in case status = 0 or an error message in case status = -1
    '''
    # TODO: revision 5
    userPass = ''
    dictU = ''
    dictOE = '' 
    dictUE = ''
    ret = computeEncryptionKey(userPassString, dictO, dictU, dictOE, dictUE, fileID, pElement, keyLength, revision, encryptMetadata)
    if ret[0] != -1:
        rc4Key = ret[1]
    else:
        return ret
    if revision == 2:
        userPass = RC4(paddingString,rc4Key)
    elif revision > 2:
        counter = 1
        md5Input = paddingString + fileID
        hashResult = hashlib.md5(md5Input).digest()
        userPass = RC4(hashResult,rc4Key)    
        while counter <= 19:
            newKey = ''
            for i in range(len(rc4Key)):
                newKey += chr(ord(rc4Key[i]) ^ counter)
            userPass = RC4(userPass,newKey)
            counter += 1
        counter = 0
        while counter < 16:
            userPass += chr(random.randint(32,255))
            counter += 1
    return (0, userPass)

def isUserPass(password, computedUserPass, dictU, revision):
    '''
        Checks if the given password is the User password of the file
        
        @param password: The given password or the empty password
        @param computedUserPass: The computed user password of the file
        @param dictU: The /U element of the /Encrypt dictionary
        @param revision: The number of revision of the standard security handler
        @return The boolean telling if the given password is the user password or not
    '''
    if revision == 5:
        vSalt = dictU[32:40]
        inputHash = hashlib.sha256(password + vSalt).digest()
        if inputHash == dictU[:32]:
            return True
        else:
            return False 
    elif revision == 3 or revision == 4:
        if computedUserPass[:16] == dictU[:16]:
            return True
        else:
            return False
    elif revision < 3:
        if computedUserPass == dictU:
            return True
        else:
            return False

def isOwnerPass(password, dictO, dictU, computedUserPass, keyLength, revision):
    '''
        Checks if the given password is the owner password of the file
        
        @param password: The given password or the empty password
        @param dictO: The /O element of the /Encrypt dictionary
        @param dictU: The /U element of the /Encrypt dictionary
        @param computedUserPass: The computed user password of the file
        @param keyLength: The length of the key
        @param revision: The algorithm revision
        @return The boolean telling if the given password is the owner password or not
    '''
    if revision == 5:
        vSalt = dictO[32:40]
        inputHash = hashlib.sha256(password + vSalt + dictU).digest()
        if inputHash == dictO[:32]:
            return True
        else:
            return False 
    else:
        keyLength = keyLength/8
        lenPass = len(password)
        if lenPass > 32:
            password = password[:32]
        elif lenPass < 32:
            password += paddingString[:32-lenPass]
        rc4Key = hashlib.md5(password).digest()
        if revision > 2:
            counter = 0
            while counter < 50:
                rc4Key = hashlib.md5(rc4Key).digest()
                counter += 1
        rc4Key = rc4Key[:keyLength]
        if revision == 2:
            userPass = RC4(dictO, rc4Key)
        elif revision > 2:
            counter = 19
            while counter >= 0:
                newKey = ''
                for i in range(len(rc4Key)):
                    newKey += chr(ord(rc4Key[i]) ^ counter)
                dictO = RC4(dictO,newKey)
                counter -= 1
            userPass = dictO
        else:
            # Is it possible??
            userPass = ''
        return isUserPass(userPass, computedUserPass, dictU, revision)
    
def RC4(data, key):
    '''
        RC4 implementation
        
        @param data: Bytes to be encrypyed/decrypted
        @param key: Key used for the algorithm
        @return: The encrypted/decrypted bytes
    '''    
    y = 0
    hash = {}
    box = {}
    ret = ''
    keyLength  = len(key)
    dataLength = len(data)
      
    #Initialization
    for x in range(256):
        hash[x] = ord(key[x % keyLength])
        box[x]    = x  
    for x in range(256):
        y            = (y + int(box[x]) + int(hash[x])) % 256 
        tmp        = box[x]
        box[x] = box[y]
        box[y] = tmp 

    z = y = 0
    for x in range(0,dataLength):
        z = (z + 1) % 256 
        y = (y + box[z]) % 256
        tmp    = box[z]
        box[z] = box[y]
        box[y] = tmp
        k    = box[((box[z] + box[y]) % 256)]
        ret    += chr(ord(data[x]) ^ k)
    return ret

'''
    Author: Evan Fosmark (http://www.evanfosmark.com/2008/06/xor-encryption-with-python/)
'''
def xor(bytes, key):
    '''
        Simple XOR implementation
        
        @param bytes: Bytes to be xored
        @param key: Key used for the operation, it's cycled.
        @return: The xored bytes
    '''
    key = cycle(key)
    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(bytes, key))