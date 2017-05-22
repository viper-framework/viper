# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.bytecodes.apk import APK, androconf
    from androguard.core.analysis import analysis
    from androguard.decompiler.decompiler import DecompilerDAD, DecompilerDed, DecompilerDex2Jad
    from androguard.decompiler.dad.decompile import DvMethod
    HAVE_ANDROGUARD = True
except Exception:
    HAVE_ANDROGUARD = False


class AndroidPackage(Module):
    cmd = 'apk'
    description = 'Parse Android Applications'
    authors = ['Kevin Breen']

    def __init__(self):
        super(AndroidPackage, self).__init__()
        self.parser.add_argument('-i', '--info', action='store_true', help='Show general info')
        self.parser.add_argument('-p', '--perm', action='store_true', help='Show APK permissions')
        self.parser.add_argument('-f', '--file', action='store_true', help='Show APK file list')
        self.parser.add_argument('-u', '--url', action='store_true', help='Show URLs in APK')
        self.parser.add_argument('-a', '--all', action='store_true', help='Run all options excluding dump')
        self.parser.add_argument('-d', '--dump', metavar='dump_path', help='Extract all items from archive')

    def run(self):

        def analyze_apk(filename, raw=False, decompiler=None):
            """
            Analyze an android application and setup all stuff for a more quickly analysis !

            :param filename: the filename of the android application or a buffer which represents the application
            :type filename: string
            :param raw: True is you would like to use a buffer (optional)
            :type raw: boolean
            :param decompiler: ded, dex2jad, dad (optional)
            :type decompiler: string

            :rtype: return the :class:`APK`, :class:`DalvikVMFormat`, and :class:`VMAnalysis` objects
            """

            a = APK(filename, raw)
            d, dx = analyze_dex(a.get_dex(), raw=True, decompiler=decompiler)
            return a, d, dx

        def analyze_dex(filename, raw=False, decompiler=None):
            """
            Analyze an android dex file and setup all stuff for a more quickly analysis !

            :param filename: the filename of the android dex file or a buffer which represents the dex file
            :type filename: string
            :param raw: True is you would like to use a buffer (optional)
            :type raw: boolean
            :param decompiler: the type of decompiler to use ("dad", "dex2jad", "ded")
            :type decompiler: string

            :rtype: return the :class:`DalvikVMFormat`, and :class:`VMAnalysis` objects
            """
            d = None
            if raw:
                d = DalvikVMFormat(filename)
            else:
                d = DalvikVMFormat(open(filename, "rb").read())
            dx = analysis.Analysis(d)
            d.set_vmanalysis(dx)
            run_decompiler(d, dx, decompiler)
            dx.create_xref()
            return d, dx

        def run_decompiler(d, dx, decompiler):
            """
            Run the decompiler on a specific analysis

            :param d: the DalvikVMFormat object
            :type d: :class:`DalvikVMFormat` object
            :param dx: the analysis of the format
            :type dx: :class:`VMAnalysis` object
            :param decompiler: the type of decompiler to use ("dad", "dex2jad", "ded")
            :type decompiler: string
            """
            if decompiler is not None:
                decompiler = decompiler.lower()
                if decompiler == "dex2jad":
                    d.set_decompiler(DecompilerDex2Jad(d, androconf.CONF["PATH_DEX2JAR"], androconf.CONF["BIN_DEX2JAR"],
                                                       androconf.CONF["PATH_JAD"], androconf.CONF["BIN_JAD"],
                                                       androconf.CONF["TMP_DIRECTORY"]))
                elif decompiler == "ded":
                    d.set_decompiler(DecompilerDed(d, androconf.CONF["PATH_DED"], androconf.CONF["BIN_DED"],
                                                   androconf.CONF["TMP_DIRECTORY"]))
                elif decompiler == "dad":
                    d.set_decompiler(DecompilerDAD(d, dx))
                else:
                    self.log('info', "Unknown decompiler, use DAD decompiler by default")
                    d.set_decompiler(DecompilerDAD(d, dx))

        # List all files and types
        def andro_file(a):
            self.log('info', "APK Contents")
            rows = []
            for file_name, file_type in a.files.items():
                rows.append([file_name, file_type])
            self.log('table', dict(header=['File Name', 'File Type'], rows=rows))

        # List general info
        def andro_info(a):
            self.log('info', "APK General Information")
            self.log('item', "Package Name: {0}".format(a.package))
            self.log('item', "Version Code: {0}".format(a.androidversion['Code']))
            self.log('item', "Valid APK: {0}".format(a.is_valid_APK()))
            self.log('item', "Main Activity: {0}".format(a.get_main_activity()))
            self.log('info', "Other Activities")
            for item in a.get_activities():
                self.log('item', item)
            self.log('info', "Services")
            for item in a.get_services():
                self.log('item', item)
            self.log('info', "Receivers")
            for item in a.get_receivers():
                self.log('item', item)

        # List all the permisisons
        def andro_perm(a):
            self.log('info', "APK Permissions")
            for perms in a.permissions:
                self.log('item', perms)

        # List all URL in the dex file
        def andro_url(vm):
            url_set = vm.get_regex_strings("http(s){0,1}://")
            self.log('info', "APK URLs")
            for url in url_set:
                self.log('item', url.encode('utf-8'))

        # Decompile and Dump all the methods
        def andro_dump(vm, vmx, dump_path):
            # Export each decompiled method
            for method in vm.get_methods():
                mx = vmx.get_method(method)

                if method.get_code() is None:
                    continue
                ms = DvMethod(mx)
                ms.process()
                with open(dump_path, 'a+') as outfile:
                    outfile.write(str(method.get_class_name()))
                    outfile.write(str(method.get_name()) + '\n')
                    outfile.write(ms.get_source())
                    outfile.write('\n')

        def process_apk():
            # Process the APK File
            try:
                self.log('info', "Processing the APK, this may take a moment...")
                APK_FILE = __sessions__.current.file.path
                a, vm, vmx = analyze_apk(APK_FILE, decompiler='dad')
                return a, vm, vmx
            except AttributeError as e:
                self.log('error', "Error: {0}".format(e))
                return False, False, False

        def _load_params():
            a = None
            vm = None
            vmx = None

            if hasattr(__sessions__.current, 'param_a'):
                a = __sessions__.current.param_a
            if hasattr(__sessions__.current, 'param_vm'):
                vm = __sessions__.current.param_vm
            if hasattr(__sessions__.current, 'param_vmx'):
                vmx = __sessions__.current.param_vmx

            if not a or not vm or not vmx:
                a, vm, vmx = process_apk()
                __sessions__.current.param_a = a
                __sessions__.current.param_vm = vm
                __sessions__.current.param_vmx = vmx

            return a, vm, vmx

        super(AndroidPackage, self).run()
        if self.args is None:
            return

        # Check for session
        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        # Check for androguard
        if not HAVE_ANDROGUARD:
            self.log('error', "Unable to import AndroGuard")
            self.log('error', "Install https://github.com/androguard/androguard/archive/v2.0.tar.gz")
            return

        a, vm, vmx = _load_params()
        if not a:
            return
        if self.args.dump is not None:
            self.log('info', "Decompiling Code")
            andro_dump(vm, vmx, self.args.dump)
            self.log('info', "Decompiled code saved to {0}".format(self.args.dump))
        elif self.args.info:
            andro_info(a)
        elif self.args.perm:
            andro_perm(a)
        elif self.args.file:
            andro_file(a)
        elif self.args.url:
            andro_url(vm)
        elif self.args.all:
            andro_info(a)
            andro_perm(a)
            andro_file(a)
        else:
            self.log('error', 'At least one of the parameter is required')
            self.usage()
