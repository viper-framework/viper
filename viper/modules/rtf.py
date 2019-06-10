# -*- coding: utf-8 -*-

'''
Code based on the python-oletools package by Philippe Lagadec 2012-10-18
http://www.decalage.info/python/oletools
'''

import os
import sys
import tempfile

from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    from oletools import rtfobj
    from oletools.rtfobj import RtfObjParser
    from oletools.rtfobj import RtfObject
    from oletools.rtfobj import sanitize_filename
    from oletools import oleobj
    import olefile
    from oletools.common import clsid 

    HAVE_RTF = True
except ImportError:
    HAVE_RTF = False


class Rtf(Module):
    cmd = 'rtf'
    description = 'RTF Parser'
    authors = ['xorhex']

    def __init__(self):
        super(Rtf, self).__init__()
        self.parser.add_argument('-l', "--list", action='store_true', help='List of ')
        self.parser.add_argument('-s', "--save", metavar='item_index', help='Save object')

    def parse_rtf(self, filename, data):
        '''
          The bulk of this fuction is taken from python-oletools: https://github.com/decalage2/oletools/blob/master/oletools/rtfobj.py
          See link for license
        '''
        self.log('success', 'File: {name} - size: {size} bytes'.format(name=filename, size=hex(len(data))))
        table = []
        h = ['id','index','OLE Object']
        
        rtfp = RtfObjParser(data)
        rtfp.parse()
        for rtfobj in rtfp.objects:
            row = []
            obj_col = []
            if rtfobj.is_ole:
                obj_col.append('format_id: {id} '.format(id=rtfobj.format_id))
                if rtfobj.format_id == oleobj.OleObject.TYPE_EMBEDDED:
                    obj_col.append('(Embedded)')
                elif rtfobj.format_id == oleobj.OleObject.TYPE_LINKED:
                    obj_col.append('(Linked)')
                else:
                    obj_col.append('(Unknown)')
                obj_col.append('class name: {cls}'.format(cls=rtfobj.class_name))
                # if the object is linked and not embedded, data_size=None:
                if rtfobj.oledata_size is None:
                    obj_col.append('data size: N/A')
                else:
                    obj_col.append('data size: %d' % rtfobj.oledata_size)
                if rtfobj.is_package:
                    obj_col.append('OLE Package object:')
                    obj_col.append('Filename: {name}'.format(name=rtfobj.filename))
                    obj_col.append('Source path: {path}'.format(path=rtfobj.src_path))
                    obj_col.append('Temp path = {path}'.format(path=rtfobj.temp_path))
                    obj_col.append('MD5 = {md5}'.format(md5=rtfobj.olepkgdata_md5))
                    # check if the file extension is executable:

                    _, temp_ext = os.path.splitext(rtfobj.temp_path)
                    self.log('debug', 'Temp path extension: {ext}'.format(ext=temp_ext))
                    _, file_ext = os.path.splitext(rtfobj.filename)
                    log.debug('File extension: %r' % file_ext)

                    if temp_ext != file_ext:
                        obj_col.append("MODIFIED FILE EXTENSION")

                    if re_executable_extensions.match(temp_ext) or re_executable_extensions.match(file_ext):
                        obj_col.append('EXECUTABLE FILE')
                else:
                    obj_col.append('MD5 = {md5}'.format(md5=rtfobj.oledata_md5))
                if rtfobj.clsid is not None:
                    obj_col.append('CLSID: {clsid}'.format(clsid=rtfobj.clsid))
                    obj_col.append(rtfobj.clsid_desc)
                # Detect OLE2Link exploit
                # http://www.kb.cert.org/vuls/id/921560
                if rtfobj.class_name == b'OLE2Link':
                    obj_col.append('Possibly an exploit for the OLE2Link vulnerability (VU#921560, CVE-2017-0199)')
                # Detect Equation Editor exploit
                # https://www.kb.cert.org/vuls/id/421280/
                elif rtfobj.class_name.lower() == b'equation.3':
                    obj_col.append('Possibly an exploit for the Equation Editor vulnerability (VU#421280, CVE-2017-11882)')
            else:
                obj_col.append('Not a well-formed OLE object')

            row.append(rtfp.objects.index(rtfobj))
            row.append('%08Xh' % rtfobj.start)
            row.append('\n'.join(obj_col))
            table.append(row)

        self.log('table', dict(rows=table, header=h))

    def list(self):
       self.parse_rtf(__sessions__.current.file.name, __sessions__.current.file.data) 

    def save_ole_objects(self, data, save_object, filename):
        '''
          The bulk of this fuction is taken from python-oletools: https://github.com/decalage2/oletools/blob/master/oletools/rtfobj.py
          See link for license
        '''

        base_dir = os.path.dirname(filename)
        sane_fname = sanitize_filename(filename)
        fname_prefix = os.path.join(base_dir, sane_fname)

        rtfp = RtfObjParser(data)
        rtfp.parse()

        try:
            i = int(save_object)
            objects = [ rtfp.objects[i] ]
        except:
            self.log('error', 'The -s option must be followed by an object index, such as "-s 2"')
            return
        for rtfobj in objects:
            i = objects.index(rtfobj)
            tmp = tempfile.NamedTemporaryFile(delete=False)
            if rtfobj.is_package:
                self.log('info', 'Saving file from OLE Package in object #%d:' % i)
                self.log('info', '  Filename = %r' % rtfobj.filename)
                self.log('info', '  Source path = %r' % rtfobj.src_path)
                self.log('info', '  Temp path = %r' % rtfobj.temp_path)
                if rtfobj.filename:
                    fname = '%s_%s' % (fname_prefix,
                                       sanitize_filename(rtfobj.filename))
                else:
                    fname = '%s_object_%08X.noname' % (fname_prefix, rtfobj.start)
                #self.log('info', '  saving to file %s' % fname)
                self.log('info', '  saving to file %s' % tmp.name)
                self.log('info', '  md5 %s' % rtfobj.olepkgdata_md5)
                tmp.write(rtfobj.olepkgdata)
                tmp.close()
            # When format_id=TYPE_LINKED, oledata_size=None
            elif rtfobj.is_ole and rtfobj.oledata_size is not None:
                self.log('info', 'Saving file embedded in OLE object #%d:' % i)
                self.log('info', '  format_id  = %d' % rtfobj.format_id)
                self.log('info', '  class name = %r' % rtfobj.class_name)
                self.log('info', '  data size  = %d' % rtfobj.oledata_size)
                # set a file extension according to the class name:
                class_name = rtfobj.class_name.lower()
                if class_name.startswith(b'word'):
                    ext = 'doc'
                elif class_name.startswith(b'package'):
                    ext = 'package'
                else:
                    ext = 'bin'
                fname = '%s_object_%08X.%s' % (fname_prefix, rtfobj.start, ext)
                #self.log('info', '  saving to file %s' % fname)
                self.log('info', '  saving to file %s' % tmp.name)
                self.log('info', '  md5 %s' % rtfobj.oledata_md5)
                tmp.write(rtfobj.oledata)
                tmp.close()
            else:
                self.log('info', 'Saving raw data in object #%d:' % i)
                fname = '%s_object_%08X.raw' % (fname_prefix, rtfobj.start)
                #self.log('info', '  saving object to file %s' % fname)
                self.log('info', '  saving object to file %s' % tmp.name)
                self.log('info', '  md5 %s' % rtfobj.rawdata_md5)
                tmp.write(rtfobj.rawdata)
                tmp.close()

        if not save_object == 'all':
            __sessions__.new(tmp.name)


    def save(self, idx):
        self.save_ole_objects(__sessions__.current.file.data, idx, __sessions__.current.file.name)

    # Main starts here
    def run(self):
        super(Rtf, self).run()
        if self.args is None:
            return
        if not __sessions__.is_set():
            self.log('error', 'No open session. This command expects a file to be open.')
            return
        
        if not HAVE_RTF:
            self.log('error', 'Missing dependancy.  install oletools (pip install oletools)')
            return

        if self.args.list:
            self.list()
        elif self.args.save:
            self.save(self.args.save)
        else:
            self.parser.print_usage()