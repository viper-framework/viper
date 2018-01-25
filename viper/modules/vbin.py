# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    import idb
    HAVE_PYIDB = True
except ImportError:
    HAVE_PYIDB = False


class vBin(Module):
    cmd = 'vbin'
    description = 'Viper binary analysis (vBin) module to inspect the sample'
    authors = ['emdel']

    def __init__(self):
        super(vBin, self).__init__()
        subparsers = self.parser.add_subparsers(dest='subname')
        subparsers.add_parser('functions', help='List functions in the IDB')
        disass_parser = subparsers.add_parser('disass', help='Disassemble functions from the IDB')
        disass_parser.add_argument('-f', '--function', help='Specify the function name')
        calls_parser = subparsers.add_parser('calls', help='List calls inside a function')
        calls_parser.add_argument('-f', '--function', help='Specify the function name')

    def get_current_file_dir(self, filename):
        return filename + ".dir"

    def get_current_idb_path(self, path):
        return os.path.join(path, "executable.idb")

    def get_current_idb_path64(self, path):
        return os.path.join(path, "executable.i64")

    def get_db(self, current_idb):
        h_idb = open(current_idb, "rb")
        idb_data = h_idb.read()
        h_idb.close()
        return idb.from_buffer(idb_data)

    def list_functions(self, db):
        api = idb.IDAPython(db)
        for ea in api.idautils.Functions():
            name = api.idc.GetFunctionName(ea)
            self.log('info', "%x: %s" % (ea, name))

    def disass(self, db, func_name):
        api = idb.IDAPython(db)
        found = 0
        for ea in api.idautils.Functions():
            name = api.idc.GetFunctionName(ea)
            if name == func_name:
                found = 1
                break
        if found == 0:
            self.log('error', "Function %s not found" % func_name)
            return
        fx_start = ea
        fx_end = api.ida_funcs.get_func(fx_start).endEA
        self.log("info", "Function start at: %x" % fx_start)
        self.log("info", "Function end at: %x" % fx_end)
        heads = []
        heads.append(fx_start)
        for addr in range(fx_start, fx_end):
            a = api.idc.NextHead(addr)
            heads.append(a)
        for h in sorted(set(heads)):
            try:
                op = api.idc._disassemble(h)
                code = "{0}: {1} {2}".format(hex(h), op.mnemonic, op.op_str)
                print(code)
            except (ValueError, RuntimeError) as error:
                self.log("error", error)
                continue

    def show_calls(self, db, func_name):
        api = idb.IDAPython(db)
        found = 0
        for ea in api.idautils.Functions():
            name = api.idc.GetFunctionName(ea)
            if name == func_name:
                found = 1
                break
        if found == 0:
            self.log('error', "Function %s not found" % func_name)
            return
        fx_start = ea
        fx_end = api.ida_funcs.get_func(fx_start).endEA
        heads = []
        for addr in range(fx_start, fx_end):
            a = api.idc.NextHead(addr)
            heads.append(a)
        for h in set(heads):
            try:
                op = api.idc._disassemble(h)
                if op.mnemonic != "call":
                    continue
                code = "{0}: {1} {2}".format(hex(h), op.mnemonic, op.op_str)
                print(code)
            except Exception:
                continue

    def run(self):
        super(vBin, self).run()
        if self.args is None:
            return

        if not HAVE_PYIDB:
            self.log('error', "Missing dependancy, install python-idb")
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        current_file = __sessions__.current.file.path
        current_dir = self.get_current_file_dir(current_file)
        current_idb = self.get_current_idb_path(current_dir)

        if not os.path.exists(current_idb):
            current_idb = self.get_current_idb_path64(current_dir)

        # Loading IDB
        db = self.get_db(current_idb)

        if self.args.subname == "functions":
            self.list_functions(db)
        elif self.args.subname == "disass":
            func_name = self.args.function
            self.disass(db, func_name)
        elif self.args.subname == "calls":
            func_name = self.args.function
            self.show_calls(db, func_name)
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
