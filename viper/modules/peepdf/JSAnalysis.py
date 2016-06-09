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
    This module contains some functions to analyse Javascript code inside the PDF file
'''

import sys, re , os, jsbeautifier, traceback
from PDFUtils import unescapeHTMLEntities, escapeString
try:
    import PyV8
    
    JS_MODULE = True
    
    class Global(PyV8.JSClass):
        evalCode = ''
        
        def evalOverride(self, expression):
            self.evalCode += '\n\n// New evaluated code\n' + expression
            return
        
except:
    JS_MODULE = False


errorsFile = 'errors.txt'
newLine = os.linesep         
reJSscript = '<script[^>]*?contentType\s*?=\s*?[\'"]application/x-javascript[\'"][^>]*?>(.*?)</script>'
preDefinedCode = 'var app = this;'

def analyseJS(code, context = None, manualAnalysis = False):
    '''
        Hooks the eval function and search for obfuscated elements in the Javascript code
        
        @param code: The Javascript code (string)
        @return: List with analysis information of the Javascript code: [JSCode,unescapedBytes,urlsFound,errors,context], where 
                JSCode is a list with the several stages Javascript code,
                unescapedBytes is a list with the parameters of unescape functions, 
                urlsFound is a list with the URLs found in the unescaped bytes,
                errors is a list of errors,
                context is the context of execution of the Javascript code.
    '''
    errors = []
    JSCode = []
    unescapedBytes = []
    urlsFound = []
    
    try:
        code = unescapeHTMLEntities(code)
        scriptElements = re.findall(reJSscript, code, re.DOTALL | re.IGNORECASE)
        if scriptElements != []:
            code = ''
            for scriptElement in scriptElements:
                code += scriptElement + '\n\n'
        code = jsbeautifier.beautify(code)
        JSCode.append(code)
    
        if code != None and JS_MODULE and not manualAnalysis:
            if context == None:
                context = PyV8.JSContext(Global())
            context.enter()
            # Hooking the eval function
            context.eval('eval=evalOverride')
            #context.eval(preDefinedCode)
            while True:
                originalCode = code
                try:
                    context.eval(code)
                    evalCode = context.eval('evalCode')
                    evalCode = jsbeautifier.beautify(evalCode)
                    if evalCode != '' and evalCode != code:
                        code = evalCode
                        JSCode.append(code)
                    else:
                        break
                except:
                    error = str(sys.exc_info()[1])
                    open('jserror.log','ab').write(error + newLine)
                    errors.append(error)
                    break
            
            if code != '':
                escapedVars = re.findall('(\w*?)\s*?=\s*?(unescape\((.*?)\))', code, re.DOTALL)
                for var in escapedVars:
                    bytes = var[2]
                    if bytes.find('+') != -1 or bytes.find('%') == -1:
                        varContent = getVarContent(code, bytes)
                        if len(varContent) > 150:
                            ret = unescape(varContent)
                            if ret[0] != -1:
                                bytes = ret[1]
                                urls = re.findall('https?://.*$', bytes, re.DOTALL)
                                if bytes not in unescapedBytes:
                                   unescapedBytes.append(bytes)
                                for url in urls:
                                   if url not in urlsFound:
                                       urlsFound.append(url)
                    else:
                        bytes = bytes[1:-1]
                        if len(bytes) > 150:
                            ret = unescape(bytes)
                            if ret[0] != -1:
                                bytes = ret[1]
                                urls = re.findall('https?://.*$', bytes, re.DOTALL)
                                if bytes not in unescapedBytes:
                                   unescapedBytes.append(bytes)
                                for url in urls:
                                   if url not in urlsFound:
                                       urlsFound.append(url)
    except:
        traceback.print_exc(file=open(errorsFile,'a'))
        errors.append('Unexpected error in the JSAnalysis module!!')
    finally:
        for js in JSCode:
            if js == None or js == '':
                 JSCode.remove(js)
    return [JSCode,unescapedBytes,urlsFound,errors,context]
 
def getVarContent(jsCode, varContent):
    '''
        Given the Javascript code and the content of a variable this method tries to obtain the real value of the variable, cleaning expressions like "a = eval; a(js_code);"
        
        @param jsCode: The Javascript code (string)
        @param varContent: The content of the variable (string)
        @return: A string with real value of the variable
    '''
    clearBytes = ''
    varContent = varContent.replace('\n','')
    varContent = varContent.replace('\r','')
    varContent = varContent.replace('\t','')
    varContent = varContent.replace(' ','')
    parts = varContent.split('+')
    for part in parts:
        if re.match('["\'].*?["\']', part, re.DOTALL):
            clearBytes += part[1:-1]
        else:
            part = escapeString(part)
            varContent = re.findall(part + '\s*?=\s*?(.*?)[,;]', jsCode, re.DOTALL)
            if varContent != []:
                clearBytes += getVarContent(jsCode, varContent[0])
    return clearBytes

def isJavascript(content):
    '''
        Given an string this method looks for typical Javscript strings and try to identify if the string contains Javascrit code or not.
        
        @param content: A string
        @return: A boolean, True if it seems to contain Javascript code or False in the other case
    '''
    JSStrings = ['var ',';',')','(','function ','=','{','}','if ','else','return','while ','for ',',','eval']
    keyStrings = [';','(',')']
    stringsFound = []
    limit = 15
    minDistinctStringsFound = 5
    results = 0
    
    if re.findall(reJSscript, content, re.DOTALL | re.IGNORECASE) != []:
        return True
    
    for char in content:
        if (ord(char) < 32 and char not in ['\n','\r','\t','\f','\x00']) or ord(char) >= 127:
            return False

    for string in JSStrings:
        cont = content.count(string)
        results += cont
        if cont > 0 and string not in stringsFound:
            stringsFound.append(string)
        elif cont == 0 and string in keyStrings:
            return False

    if results > limit and len(stringsFound) >= minDistinctStringsFound:
        return True
    else:
        return False
    
def searchObfuscatedFunctions(jsCode, function):
    '''
        Search for obfuscated functions in the Javascript code
        
        @param jsCode: The Javascript code (string)
        @param function: The function name to look for (string)
        @return: List with obfuscated functions information [functionName,functionCall,containsReturns] 
    '''
    obfuscatedFunctionsInfo = []
    if jsCode != None:
        match = re.findall('\W('+function+'\s{0,5}?\((.*?)\)\s{0,5}?;)', jsCode, re.DOTALL)
        if match != []:
           for m in match:
              if re.findall('return',m[1],re.IGNORECASE) != []:
                 obfuscatedFunctionsInfo.append([function,m,True])
              else:
                 obfuscatedFunctionsInfo.append([function,m,False])
        obfuscatedFunctions = re.findall('\s*?((\w*?)\s*?=\s*?'+function+')\s*?;', jsCode, re.DOTALL)
        for obfuscatedFunction in obfuscatedFunctions:
           obfuscatedElement = obfuscatedFunction[1]
           obfuscatedFunctionsInfo += searchObfuscatedFunctions(jsCode, obfuscatedElement)
    return obfuscatedFunctionsInfo

def unescape(escapedBytes, unicode = True):
    '''
        This method unescapes the given string
        
        @param escapedBytes: A string to unescape
        @return: A tuple (status,statusContent), where statusContent is an unescaped string in case status = 0 or an error in case status = -1
    '''
    #TODO: modify to accept a list of escaped strings?
    unescapedBytes = ''
    if unicode:
        unicodePadding = '\x00'
    else:
        unicodePadding = ''
    try:
        if escapedBytes.lower().find('%u') != -1 or escapedBytes.lower().find('\u') != -1 or escapedBytes.find('%') != -1:
            if escapedBytes.lower().find('\u') != -1:
                splitBytes = escapedBytes.split('\\')
            else:
                splitBytes = escapedBytes.split('%')
            for i in range(len(splitBytes)):
                splitByte = splitBytes[i]
                if splitByte == '':
                    continue
                if len(splitByte) > 4 and re.match('u[0-9a-f]{4}',splitByte[:5],re.IGNORECASE):
                    unescapedBytes += chr(int(splitByte[3]+splitByte[4],16))+chr(int(splitByte[1]+splitByte[2],16))
                    if len(splitByte) > 5:
                        for j in range(5,len(splitByte)): 
                            unescapedBytes += splitByte[j] + unicodePadding
                elif len(splitByte) > 1 and re.match('[0-9a-f]{2}',splitByte[:2],re.IGNORECASE):
                    unescapedBytes += chr(int(splitByte[0]+splitByte[1],16)) + unicodePadding
                    if len(splitByte) > 2:
                        for j in range(2,len(splitByte)): 
                            unescapedBytes += splitByte[j] + unicodePadding
                else:
                    if i != 0:
                        unescapedBytes += '%' + unicodePadding
                    for j in range(len(splitByte)):
                        unescapedBytes += splitByte[j] + unicodePadding
        else:
            unescapedBytes = escapedBytes
    except:
        return (-1,'Error while unescaping the bytes')
    return (0,unescapedBytes)