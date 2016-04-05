#
#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2014 Jose Miguel Esparza
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

# Python version of the jjdecode function written by Syed Zainudeen
# http://csc.cs.utm.my/syed/images/files/jjdecode/jjdecode.html
# +NCR/CRC! [ReVeRsEr] - crackinglandia@gmail.com
#
# The original algorithm was written in Javascript by Yosuke Hasegawa (http://utf-8.jp/public/jjencode.html)
#
# Modified to integrate it with peepdf

import re, sys

class JJDecoder(object):

    def __init__(self, jj_encoded_data):
        self.encoded_str = jj_encoded_data
        
    def clean(self):
        self.encoded_str = re.sub('^\s+|\s+$', '', self.encoded_str)
        
    def checkPalindrome(self):
        startpos = -1
        endpos = -1
        gv, gvl = -1, -1

        index = self.encoded_str.find('"\'\\"+\'+",')

        if index == 0:
            startpos = self.encoded_str.find('$$+"\\""+') + 8
            endpos = self.encoded_str.find('"\\"")())()')
            gv = self.encoded_str[index+9:self.encoded_str.find('=~[]')]
            gvl = len(gv)
        else:
            gv = self.encoded_str[0:self.encoded_str.find('=')]
            gvl = len(gv)
            startpos = self.encoded_str.find('"\\""+') + 5
            endpos = self.encoded_str.find('"\\"")())()')

        return (startpos, endpos, gv, gvl)
        
    def decode(self):
        
        self.clean()
        startpos, endpos, gv, gvl = self.checkPalindrome()
        
        if startpos == endpos:
            return (-1,'There is no data to decode')

        data = self.encoded_str[startpos:endpos]

        b = ['___+', '__$+', '_$_+', '_$$+', '$__+', '$_$+', '$$_+', '$$$+', '$___+', '$__$+', '$_$_+', '$_$$+', '$$__+', '$$_$+', '$$$_+', '$$$$+']

        str_l = '(![]+"")[' + gv + '._$_]+'
        str_o     = gv + '._$+'
        str_t = gv + '.__+'
        str_u = gv + '._+'
        
        str_hex = gv + '.'

        str_s = '"'
        gvsig = gv + '.'

        str_quote = '\\\\\\"'
        str_slash = '\\\\\\\\'

        str_lower = '\\\\"+'
        str_upper = '\\\\"+' + gv + '._+'

        str_end    = '"+'

        out = ''
        while data != '':
            # l o t u
            if data.find(str_l) == 0:
                data = data[len(str_l):]
                out += 'l'
                continue
            elif data.find(str_o) == 0:
                data = data[len(str_o):]
                out += 'o'
                continue
            elif data.find(str_t) == 0:
                data = data[len(str_t):]
                out += 't'
                continue
            elif data.find(str_u) == 0:
                data = data[len(str_u):]
                out += 'u'
                continue

            # 0123456789abcdef
            if data.find(str_hex) == 0:
                data = data[len(str_hex):]
                
                for i in range(len(b)):
                    if data.find(b[i]) == 0:
                        data = data[len(b[i]):]
                        out += '%x' % i
                        break
                continue

            # start of s block
            if data.find(str_s) == 0:
                data = data[len(str_s):]

                # check if "R
                if data.find(str_upper) == 0: # r4 n >= 128
                    data = data[len(str_upper):] # skip sig
                    ch_str = ''
                    for i in range(2): # shouldn't be more than 2 hex chars
                        # gv + "."+b[ c ]
                        if data.find(gvsig) == 0:
                            data = data[len(gvsig):]
                            for k in range(len(b)): # for every entry in b
                                if data.find(b[k]) == 0:
                                    data = data[len(b[k]):]
                                    ch_str = '%x' % k
                                    break
                        else:
                            break

                    out += chr(int(ch_str, 16))
                    continue

                elif data.find(str_lower) == 0: # r3 check if "R // n < 128
                    data = data[len(str_lower):] # skip sig
                    
                    ch_str = ''
                    ch_lotux = ''
                    temp = ''
                    b_checkR1 = 0
                    for j in range(3): # shouldn't be more than 3 octal chars
                        if j > 1: # lotu check
                            if data.find(str_l) == 0:
                                data = data[len(str_l):]
                                ch_lotux = 'l'
                                break
                            elif data.find(str_o) == 0:
                                data = data[len(str_o):]
                                ch_lotux = 'o'
                                break
                            elif data.find(str_t) == 0:
                                data = data[len(str_t):]
                                ch_lotux = 't'
                                break
                            elif data.find(str_u) == 0:
                                data = data[len(str_u):]
                                ch_lotux = 'u'
                                break

                        # gv + "."+b[ c ]
                        if data.find(gvsig) == 0:
                            temp = data[len(gvsig):]
                            for k in range(8): # for every entry in b octal
                                if temp.find(b[k]) == 0:
                                    if int(ch_str + str(k), 8) > 128:
                                        b_checkR1 = 1
                                        break

                                    ch_str += str(k)
                                    data = data[len(gvsig):] # skip gvsig
                                    data = data[len(b[k]):]
                                    break

                            if b_checkR1 == 1:
                                if data.find(str_hex) == 0: # 0123456789abcdef
                                    data = data[len(str_hex):]
                                    # check every element of hex decode string for a match
                                    for i in range(len(b)):
                                        if data.find(b[i]) == 0:
                                            data = data[len(b[i]):]
                                            ch_lotux = '%x' % i
                                            break
                                    break
                        else:
                            break

                    out += chr(int(ch_str,8)) + ch_lotux
                    continue

                else: # "S ----> "SR or "S+
                    # if there is, loop s until R 0r +
                    # if there is no matching s block, throw error
                    
                    match = 0;
                    n = None

                    # searching for matching pure s block
                    while True:
                        n = ord(data[0])
                        if data.find(str_quote) == 0:
                            data = data[len(str_quote):]
                            out += '"'
                            match += 1
                            continue
                        elif data.find(str_slash) == 0:
                            data = data[len(str_slash):]
                            out += '\\'
                            match += 1
                            continue
                        elif data.find(str_end) == 0: # reached end off S block ? +
                            if match == 0:
                                 return (-1,'+ No match S block')
                            data = data[len(str_end):]
                            break # step out of the while loop
                        elif data.find(str_upper) == 0: # r4 reached end off S block ? - check if "R n >= 128z
                            if match == 0:
                                 return (-1,'No match S block n>128')
                            data = data[len(str_upper):] # skip sig
                            
                            ch_str = ''
                            ch_lotux = ''

                            for j in range(10): # shouldn't be more than 10 hex chars
                                if j > 1: # lotu check
                                    if data.find(str_l) == 0:
                                        data = data[len(str_l):]
                                        ch_lotux = 'l'
                                        break
                                    elif data.find(str_o) == 0:
                                        data = data[len(str_o):]
                                        ch_lotux = 'o'
                                        break
                                    elif data.find(str_t) == 0:
                                        data = data[len(str_t):]
                                        ch_lotux = 't'
                                        break
                                    elif data.find(str_u) == 0:
                                        data = data[len(str_u):]
                                        ch_lotux = 'u'
                                        break

                                # gv + "."+b[ c ]
                                if data.find(gvsig) == 0:
                                    data = data[len(gvsig):] # skip gvsig
                                    for k in range(len(b)): # for every entry in b
                                        if data.find(b[k]) == 0:
                                            data = data[len(b[k]):]
                                            ch_str += '%x' % k
                                            break
                                else:
                                    break # done
                            out += chr(int(ch_str, 16))
                            break # step out of the while loop
                        elif data.find(str_lower) == 0: # r3 check if "R // n < 128
                            if match == 0:
                                return (-1,'No match S block n<128!!')

                            data = data[len(str_lower):] # skip sig

                            ch_str = ''
                            ch_lotux = ''
                            temp = ''
                            b_checkR1 = 0

                            for j in range(3): # shouldn't be more than 3 octal chars
                                if j > 1: # lotu check
                                    if data.find(str_l) == 0:
                                        data = data[len(str_l):]
                                        ch_lotux = 'l'
                                        break
                                    elif data.find(str_o) == 0:
                                        data = data[len(str_o):]
                                        ch_lotux = 'o'
                                        break
                                    elif data.find(str_t) == 0:
                                        data = data[len(str_t):]
                                        ch_lotux = 't'
                                        break
                                    elif data.find(str_u) == 0:
                                        data = data[len(str_u):]
                                        ch_lotux = 'u'
                                        break

                                # gv + "."+b[ c ]
                                if data.find(gvsig) == 0:
                                    temp = data[len(gvsig):]
                                    for k in range(8): # for every entry in b octal
                                        if temp.find(b[k]) == 0:
                                            if int(ch_str + str(k), 8) > 128:
                                                b_checkR1 = 1
                                                break

                                            ch_str += str(k)
                                            data = data[len(gvsig):] # skip gvsig
                                            data = data[len(b[k]):]
                                            break

                                    if b_checkR1 == 1:
                                        if data.find(str_hex) == 0: # 0123456789abcdef
                                            data = data[len(str_hex):]
                                            # check every element of hex decode string for a match
                                            for i in range(len(b)):
                                                if data.find(b[i]) == 0:
                                                    data = data[len(b[i]):]
                                                    ch_lotux = '%x' % i
                                                    break
                                else:
                                    break
                            out += chr(int(ch_str, 8)) + ch_lotux
                            break # step out of the while loop
                        elif (0x21 <= n and n <= 0x2f) or (0x3A <= n and n <= 0x40) or ( 0x5b <= n and n <= 0x60 ) or ( 0x7b <= n and n <= 0x7f ):
                            out += data[0]
                            data = data[1:]
                            match += 1
                    continue
            return (-1,'No match in the code!!')
            break
        return (0, out)