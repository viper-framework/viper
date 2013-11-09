import os
import getopt

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __session__
from viper.core.storage import get_sample_path

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

class YaraScan(Module):
    cmd = 'yara'
    description = 'Run Yara scan'

    def run(self):
        if not HAVE_YARA:
            print_error("Missing dependency, install yara")
            return

        try:
            opts, argv = getopt.getopt(self.args[0:], 'r:', ['rule='])
        except getopt.GetoptError as e:
            print(e)
            return

        rule_path = ''
        for opt, value in opts:
            if opt in ('-r', '--rule'):
                rule_path = value

        if not rule_path or not os.path.exists(rule_path):
            rule_path = 'data/yara/index.yara'

        if not os.path.exists(rule_path):
            print_error("No valid Yara ruleset at {0}".format(rule_path))
            return        

        rules = yara.compile(rule_path)
        paths = []

        if __session__.is_set():
            paths.append(__session__.file.path)
        else:
            db = Database()
            samples = db.find(key='all')

            for sample in samples:
                paths.append(get_sample_path(sample.sha256))

        for path in paths:
            for match in rules.match(path):
                print match.rule, path
