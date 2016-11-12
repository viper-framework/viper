# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import string
from socket import inet_pton, AF_INET6, error as socket_error

from viper.common.abstracts import Module
from viper.common.objects import File
from viper.core.session import __sessions__
from viper.core.database import Database
from viper.core.storage import get_sample_path

DOMAIN_REGEX = re.compile('([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]\.)+[a-z0-9][a-z0-9\-]*[a-z0-9]', re.IGNORECASE)
IPV4_REGEX = re.compile('[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]')
IPV6_REGEX = re.compile('((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}'
                        '|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9'
                        'A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25['
                        '0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3'
                        '})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|['
                        '1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,'
                        '4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:'
                        '))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-'
                        '5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]'
                        '{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d'
                        '\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7}'
                        ')|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d'
                        '\d|[1-9]?\d)){3}))|:)))(%.+)?', re.IGNORECASE | re.S)
PDB_REGEX = re.compile('\.pdb$', re.IGNORECASE)
URL_REGEX = re.compile('http(s){0,1}://', re.IGNORECASE)
GET_POST_REGEX = re.compile('(GET|POST) ')
HOST_REGEX = re.compile('Host: ')
USERAGENT_REGEX = re.compile('(Mozilla|curl|Wget|Opera)/.+\(.+\;.+\)', re.IGNORECASE)
EMAIL_REGEX = re.compile('[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', re.IGNORECASE)
REGKEY_REGEX = re.compile('(HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_USERS|HKEY_CURRENT_CONFIG|HKCR|HKCU|HKLM|HKU|HKCC)(/|\x5c\x5c)', re.IGNORECASE)
REGKEY2_REGEX = re.compile('(CurrentVersion|Software\\Microsoft|Windows NT|Microsoft\\Interface)')
FILE_REGEX = re.compile('\w+\.(EXE|DLL|BAT|PS|INI|PIF|SCR|DOC|DOCX|DOCM|PPT|PPTX|PPTS|XLS|XLT|XLSX|XLTX|XLSM|XLTM|ZIP|RAR)$', re.U | re.IGNORECASE)

TLD = [
    'AC', 'ACADEMY', 'ACTOR', 'AD', 'AE', 'AERO', 'AF', 'AG', 'AGENCY', 'AI', 'AL', 'AM', 'AN', 'AO', 'AQ', 'AR',
    'ARPA', 'AS', 'ASIA', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BAR', 'BARGAINS', 'BB', 'BD', 'BE', 'BERLIN', 'BEST',
    'BF', 'BG', 'BH', 'BI', 'BID', 'BIKE', 'BIZ', 'BJ', 'BLUE', 'BM', 'BN', 'BO', 'BOUTIQUE', 'BR', 'BS', 'BT',
    'BUILD', 'BUILDERS', 'BUZZ', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CAB', 'CAMERA', 'CAMP', 'CARDS', 'CAREERS', 'CAT',
    'CATERING', 'CC', 'CD', 'CENTER', 'CEO', 'CF', 'CG', 'CH', 'CHEAP', 'CHRISTMAS', 'CI', 'CK', 'CL', 'CLEANING',
    'CLOTHING', 'CLUB', 'CM', 'CN', 'CO', 'CODES', 'COFFEE', 'COM', 'COMMUNITY', 'COMPANY', 'COMPUTER', 'CONDOS',
    'CONSTRUCTION', 'CONTRACTORS', 'COOL', 'COOP', 'CR', 'CRUISES', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DANCE',
    'DATING', 'DE', 'DEMOCRAT', 'DIAMONDS', 'DIRECTORY', 'DJ', 'DK', 'DM', 'DNP', 'DO', 'DOMAINS', 'DZ', 'EC',
    'EDU', 'EDUCATION', 'EE', 'EG', 'EMAIL', 'ENTERPRISES', 'EQUIPMENT', 'ER', 'ES', 'ESTATE', 'ET', 'EU', 'EVENTS',
    'EXPERT', 'EXPOSED', 'FARM', 'FI', 'FISH', 'FJ', 'FK', 'FLIGHTS', 'FLORIST', 'FM', 'FO', 'FOUNDATION', 'FR',
    'FUTBOL', 'GA', 'GALLERY', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GIFT', 'GL', 'GLASS', 'GM', 'GN', 'GOV',
    'GP', 'GQ', 'GR', 'GRAPHICS', 'GS', 'GT', 'GU', 'GUITARS', 'GURU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HOLDINGS',
    'HOLIDAY', 'HOUSE', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IMMOBILIEN', 'IN', 'INDUSTRIES', 'INFO', 'INK',
    'INSTITUTE', 'INT', 'INTERNATIONAL', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM', 'JO', 'JOBS', 'JP', 'KAUFEN',
    'KE', 'KG', 'KH', 'KI', 'KIM', 'KITCHEN', 'KIWI', 'KM', 'KN', 'KOELN', 'KP', 'KR', 'KRED', 'KW', 'KY', 'KZ',
    'LA', 'LAND', 'LB', 'LC', 'LI', 'LIGHTING', 'LIMO', 'LINK', 'LK', 'LR', 'LS', 'LT', 'LU', 'LUXURY', 'LV', 'LY',
    'MA', 'MAISON', 'MANAGEMENT', 'MANGO', 'MARKETING', 'MC', 'MD', 'ME', 'MENU', 'MG', 'MH', 'MIL', 'MK', 'ML',
    'MM', 'MN', 'MO', 'MOBI', 'MODA', 'MONASH', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MUSEUM', 'MV', 'MW', 'MX',
    'MY', 'MZ', 'NA', 'NAGOYA', 'NAME', 'NC', 'NE', 'NET', 'NEUSTAR', 'NF', 'NG', 'NI', 'NINJA', 'NL', 'NO', 'NP',
    'NR', 'NU', 'NZ', 'OKINAWA', 'OM', 'ONION', 'ONL', 'ORG', 'PA', 'PARTNERS', 'PARTS', 'PE', 'PF', 'PG', 'PH',
    'PHOTO', 'PHOTOGRAPHY', 'PHOTOS', 'PICS', 'PINK', 'PK', 'PL', 'PLUMBING', 'PM', 'PN', 'POST', 'PR', 'PRO',
    'PRODUCTIONS', 'PROPERTIES', 'PS', 'PT', 'PUB', 'PW', 'PY', 'QA', 'QPON', 'RE', 'RECIPES', 'RED', 'RENTALS',
    'REPAIR', 'REPORT', 'REVIEWS', 'RICH', 'RO', 'RS', 'RU', 'RUHR', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SEXY',
    'SG', 'SH', 'SHIKSHA', 'SHOES', 'SI', 'SINGLES', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SOCIAL', 'SOLAR',
    'SOLUTIONS', 'SR', 'ST', 'SU', 'SUPPLIES', 'SUPPLY', 'SUPPORT', 'SV', 'SX', 'SY', 'SYSTEMS', 'SZ', 'TATTOO',
    'TC', 'TD', 'TECHNOLOGY', 'TEL', 'TF', 'TG', 'TH', 'TIENDA', 'TIPS', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO',
    'TODAY', 'TOKYO', 'TOOLS', 'TP', 'TR', 'TRAINING', 'TRAVEL', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UK', 'UNO',
    'US', 'UY', 'UZ', 'VA', 'VACATIONS', 'VC', 'VE', 'VENTURES', 'VG', 'VI', 'VIAJES', 'VILLAS', 'VISION', 'VN',
    'VOTE', 'VOTING', 'VOTO', 'VOYAGE', 'VU', 'WANG', 'WATCH', 'WED', 'WF', 'WIEN', 'WIKI', 'WORKS', 'WS',
    'XN--3BST00M', 'XN--3DS443G', 'XN--3E0B707E', 'XN--45BRJ9C', 'XN--55QW42G', 'XN--55QX5D', 'XN--6FRZ82G',
    'XN--6QQ986B3XL', 'XN--80AO21A', 'XN--80ASEHDB', 'XN--80ASWG', 'XN--90A3AC', 'XN--C1AVG', 'XN--CG4BKI',
    'XN--CLCHC0EA0B2G2A9GCD', 'XN--D1ACJ3B', 'XN--FIQ228C5HS', 'XN--FIQ64B', 'XN--FIQS8S', 'XN--FIQZ9S',
    'XN--FPCRJ9C3D', 'XN--FZC2C9E2C', 'XN--GECRJ9C', 'XN--H2BRJ9C', 'XN--I1B6B1A6A2E', 'XN--IO0A7I', 'XN--J1AMH',
    'XN--J6W193G', 'XN--KPRW13D', 'XN--KPRY57D', 'XN--L1ACC', 'XN--LGBBAT1AD8J', 'XN--MGB9AWBF', 'XN--MGBA3A4F16A',
    'XN--MGBAAM7A8H', 'XN--MGBAB2BD', 'XN--MGBAYH7GPA', 'XN--MGBBH1A71E', 'XN--MGBC0A9AZCG', 'XN--MGBERP4A5D4AR',
    'XN--MGBX4CD0AB', 'XN--NGBC5AZD', 'XN--NQV7F', 'XN--NQV7FS00EMA', 'XN--O3CW4H', 'XN--OGBPF8FL', 'XN--P1AI',
    'XN--PGBS0DH', 'XN--Q9JYB4C', 'XN--RHQV96G', 'XN--S9BRJ9C', 'XN--UNUP4Y', 'XN--WGBH1C', 'XN--WGBL6A',
    'XN--XKC2AL3HYE2A', 'XN--XKC2DL3A5EE0H', 'XN--YFRO4I67O', 'XN--YGBI2AMMX', 'XN--ZFR164B', 'XXX', 'XYZ', 'YE',
    'YT', 'ZA', 'ZM', 'ZONE', 'ZW']


class Strings(Module):
    cmd = 'strings'
    description = 'Extract strings from file'
    authors = ['nex', 'Brian Wallace', 'Christophe Vandeplas']

    def __init__(self):
        super(Strings, self).__init__()
        self.parser.add_argument('-a', '--all', action='store_true', help='Print all strings')
        self.parser.add_argument('-F', '--files', action='store_true', help='Extract filenames from strings')
        self.parser.add_argument('-H', '--hosts', action='store_true', help='Extract IP addresses and domains from strings')
        self.parser.add_argument('-N', '--network', action='store_true', help='Extract various network related strings')
        self.parser.add_argument('-I', '--interesting', action='store_true', help='Extract various interesting strings')
        self.parser.add_argument('-s', '--scan', action='store_true', help='Scan all files in the project with all the scanners')

    def extract_hosts(self, strings):
        results = []
        for entry in strings:
            to_add = False
            if IPV4_REGEX.search(entry):
                to_add = True
            elif IPV6_REGEX.search(entry):
                try:
                    inet_pton(AF_INET6, entry)
                except socket_error:
                    continue
                else:
                    to_add = True
            elif DOMAIN_REGEX.search(entry):
                if entry[entry.rfind('.') + 1:].upper() in TLD:
                    to_add = True

            if to_add:
                if entry not in results:
                    results.append(entry)

        return results

    def extract_network(self, strings):
        results = []
        for entry in strings:
            to_add = False
            if URL_REGEX.search(entry):
                to_add = True
            if GET_POST_REGEX.search(entry):
                to_add = True
            if HOST_REGEX.search(entry):
                to_add = True
            if USERAGENT_REGEX.search(entry):
                to_add = True
            if EMAIL_REGEX.search(entry):
                if entry[entry.rfind('.') + 1:].upper() in TLD:
                    to_add = True
            if to_add:
                if entry not in results:
                    results.append(entry)

        return results

    def extract_files(self, strings):
        results = []
        for entry in strings:
            to_add = False
            if FILE_REGEX.search(entry):
                to_add = True
            if to_add:
                if entry not in results:
                    results.append(entry)

        return results

    def extract_interesting(self, strings):
        results = []
        for entry in strings:
            to_add = False
            if PDB_REGEX.search(entry):
                to_add = True
            if REGKEY_REGEX.search(entry):
                to_add = True
            if REGKEY2_REGEX.search(entry):
                to_add = True
            if to_add:
                if entry not in results:
                    results.append(entry)

        return results

    def get_strings(self, f, min=4):
        '''
        String implementation see http://stackoverflow.com/a/17197027/6880819
        Extended with Unicode support
        '''
        results = []
        result = ""
        counter = 1
        wide_word = False
        for c in f.data:
            # already have something, check if the second byte is a null
            if counter == 2 and c == "\x00":
                wide_word = True
                counter += 1
                continue
            # every 2 chars we allow a 00
            if wide_word and c == "\x00" and not counter % 2:
                counter += 1
                continue
            # valid char, go to next - newlines are to be considered as the end of the string
            if c in string.printable and c not in ['\n', '\r']:
                result += c
                counter += 1
                continue
            if len(result) >= min:
                results.append(result)
            # reset the variables
            result = ""
            counter = 1
            wide_word = False
        if len(result) >= min:  # catch result at EOF
            results.append(result)
        return results

    def process_strings(self, strings, sample_name=""):
        if sample_name:
            prefix = '{} - '.format(sample_name)
        else:
            prefix = ''

        if self.args.all:
            self.log('success', '{}All strings:'.format(prefix))
            for entry in strings:
                self.log('', entry)
        if self.args.hosts:
            results = self.extract_hosts(strings)
            if results:
                self.log('success', '{}IP addresses and domains:'.format(prefix))
                for result in results:
                    self.log('item', result)
        if self.args.network:
            results = self.extract_network(strings)
            if results:
                self.log('success', '{}Network related:'.format(prefix))
                for result in results:
                    self.log('item', result)
        if self.args.files:
            results = self.extract_files(strings)
            if results:
                self.log('success', '{}Filenames:'.format(prefix))
                for result in results:
                    self.log('item', result)
        if self.args.interesting:
            results = self.extract_interesting(strings)
            if results:
                self.log('success', '{}Various interesting strings:'.format(prefix))
                for result in results:
                    self.log('item', result)

    def run(self):
        super(Strings, self).run()

        if not (self.args.all or self.args.files or self.args.hosts or self.args.network or self.args.interesting):
            self.log('error', 'At least one of the parameters is required')
            self.usage()
            return

        if self.args.scan:
            db = Database()
            samples = db.find(key='all')
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                strings = self.get_strings(File(sample_path))
                self.process_strings(strings, sample.name)
        else:
            if not __sessions__.is_set():
                self.log('error', "No open session")
                return
            if os.path.exists(__sessions__.current.file.path):
                strings = self.get_strings(__sessions__.current.file)
                self.process_strings(strings)
