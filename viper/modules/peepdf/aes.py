#
#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2012-2014 Jose Miguel Esparza
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

"""
Created from the demonstration of the pythonaes package.

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""

import sys
from aespython import key_expander, aes_cipher, cbc_mode

def decryptData(data, password = None, keyLength =  None, mode = 'CBC'):
    '''
        Method added for peepdf
    '''
    decryptedData = ''
    if keyLength == None:
        keyLength = len(password)*8
    if keyLength not in [128, 192, 256]:
        return (-1, 'Bad length key in AES decryption process')
    
    iv = map(ord, data[:16])
    key = map(ord, password)
    data = data[16:]
    if len(data) % 16 != 0:
        data = data[:-(len(data)%16)]
    keyExpander = key_expander.KeyExpander(keyLength)
    expandedKey = keyExpander.expand(key)
    aesCipher = aes_cipher.AESCipher(expandedKey)
    if mode == 'CBC':
        aesMode = cbc_mode.CBCMode(aesCipher, 16)
    aesMode.set_iv(iv)
    for i in range(0,len(data),16):
        ciphertext = map(ord,data[i:i+16])
        decryptedBytes = aesMode.decrypt_block(ciphertext)
        for byte in decryptedBytes:
            decryptedData += chr(byte)
    return (0, decryptedData) 