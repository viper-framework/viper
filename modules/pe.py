import getopt
import hashlib

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

from viper.common.out import *
from viper.common.objects import File
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.core.session import __session__

class PE(Module):
    cmd = 'pe'
    description = 'Extract information from PE32 headers'

    def __init__(self):
        self.pe = None

    def __get_filetype(self, data):
        if not HAVE_MAGIC:
            return None

        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.buffer(data)
        except:
            try:
                file_type = magic.from_buffer(data)
            except Exception:
                return None

        return file_type

    def __get_md5(self, data):
        md5 = hashlib.md5()
        md5.update(data)
        return md5.hexdigest()

    def imports(self):
        if not self.pe:
            return

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    print_info("DLL: {0}".format(entry.dll))
                    for symbol in entry.imports:
                        print_item("{0}: {1}".format(hex(symbol.address), symbol.name), tabs=1)
                except:
                    continue
    
    def exports(self):
        if not self.pe:
            return
        
        print_info("Exports:")
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print_item("{0}: {1} ({2})".format(hex(self.pe.OPTIONAL_HEADER.ImageBase + symbol.address), symbol.name, symbol.ordinal), tabs=1)

    def resources(self):
        if not self.pe:
            return

        def usage():
            print("usage: pe resources [-d=folder]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--dump (-d)\tDestination directory to store resource files in")
            print("")

        try:
            opts, argv = getopt.getopt(self.args[1:], 'hd:s', ['help', 'dump=', 'scan'])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        dump_to = None
        do_scan = False

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-d', '--dump'):
                dump_to = value
            elif opt in ('-s', '--scan'):
                do_scan = True

        def get_resources(pe):
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        resource = {}

                        if resource_type.name is not None:
                            name = str(resource_type.name)
                        else:
                            name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))

                        if name == None:
                            name = str(resource_type.struct.Id)

                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                        filetype = self.__get_filetype(data)
                                        md5 = self.__get_md5(data)
                                        language = pefile.LANG.get(resource_lang.data.lang, None)
                                        sublanguage = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)
                                        offset = ('%-8s' % hex(resource_lang.data.struct.OffsetToData)).strip()
                                        size = ('%-8s' % hex(resource_lang.data.struct.Size)).strip()

                                        resource = [name, offset, md5, size, filetype, language, sublanguage]

                                        # Dump resources if requested to and if the file currently being
                                        # processed is the opened session file.
                                        if dump_to and pe == self.pe:
                                            resource_path = os.path.join(dump_to, '{0}_{1}_{2}'.format(__session__.file.md5, offset, name))
                                            resource.append(resource_path)

                                            with open(resource_path, 'wb') as resource_handle:
                                                resource_handle.write(data)

                                        resources.append(resource)
                    except Exception as e:
                        print_error(e)
                        continue
            
            return resources

        resources = get_resources(self.pe)

        headers = ['Name', 'Offset', 'MD5', 'Size', 'File Type', 'Language', 'Sublanguage']
        if dump_to:
            headers.append('Dumped To')

        print table(headers, resources)

        if do_scan:
            print_info("Scanning the repository for matching samples...")

            db = Database()
            samples = db.find(key='all')

            matches = []
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    cur_pe = pefile.PE(sample_path)
                except:
                    continue

                cur_resources = get_resources(cur_pe)

                for cur_resource in cur_resources:
                    for resource in resources:
                        if cur_resource[2] == resource[2]:
                            matches.append([sample.name, sample.sha256, resource[2]])

            print_info("{0} relevant matches found".format(bold(len(matches))))

            if len(matches) > 0:
                print(table(header=['Name', 'SHA256', 'Resource MD5'], rows=matches))

    def imphash(self):
        if not self.pe:
            return

        def usage():
            print("usage: pe resources [-d=folder]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\t\tShow this help message")
            print("\t--scan (-s)\t\tScan for all samples with same imphash")
            print("")

        try:
            opts, argv = getopt.getopt(self.args[1:], 'hs', ['help', 'scan'])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        do_scan = False
        verbose = False

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--scan'):
                do_scan = True

        try:
            imphash = self.pe.get_imphash()
        except AttributeError:
            print_error("No imphash support, upgrade pefile to a version >= 1.2.10-139")
            return

        print_info("Imphash: {0}".format(imphash))

        if do_scan:
            print_info("Scanning the repository for matching samples...")

            db = Database()
            samples = db.find(key='all')

            matches = []
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    cur_imphash = pefile.PE(sample_path).get_imphash()
                except:
                    continue

                if imphash == cur_imphash:
                    matches.append([sample.name, sample.sha256])

            print_info("{0} relevant matches found".format(bold(len(matches))))

            if len(matches) > 0:
                print(table(header=['Name', 'SHA256'], rows=matches))

    def usage(self):
        print("usage: pe <command>")

    def help(self):
        self.usage()
        print("")
        print("Options:")
        print("\thelp\t\tShow this help message")
        print("\timports\t\tList PE imports")
        print("\texports\t\tList PE exports")
        print("\tresources\tList PE resources")
        print("\timphash\t\tGet and scan for imphash")
        print("")

    def run(self):
        if not __session__.is_set():
            print_error("No session opened")
            return

        if not HAVE_PEFILE:
            print_error("Missing dependency, install pefile (`pip install pefile`)")
            return

        try:
            self.pe = pefile.PE(__session__.file.path)
        except pefile.PEFormatError as e:
            print_error("Unable to parse PE file: {0}".format(e))
            return

        if len(self.args) == 0:
            self.help()
            return

        if self.args[0] == 'help':
            self.help()
        elif self.args[0] == 'imports':
            self.imports()
        elif self.args[0] == 'exports':
            self.exports()
        elif self.args[0] == 'resources':
            self.resources()
        elif self.args[0] == 'imphash':
            self.imphash()
