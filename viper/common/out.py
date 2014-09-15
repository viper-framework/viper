# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

from prettytable import PrettyTable

from viper.common.colors import *

def print_info(message):
    print(bold(cyan("[*]")) + " {0}".format(message))

def print_item(message, tabs=0):
    print(" {0}".format("  " * tabs) + cyan("-") + " {0}".format(message))

def print_warning(message):
    print(bold(yellow("[!]")) + " {0}".format(message))

def print_error(message):
    print(bold(red("[!]")) + " {0}".format(message))

def print_success(message):
    print(bold(green("[+]")) + " {0}".format(message))

def table(header, rows):
    table = PrettyTable(header)
    table.align = 'l'
    table.padding_width = 1

    for row in rows:
        table.add_row(row)

    return table
