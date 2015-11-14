# This file is part of Viper - https://github.com/viper-framework/viper
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

def print_output(output, filename=None):
    if not output:
        return
    if filename:
        with open(filename.strip(), 'a') as out:
            for entry in output:
                if entry['type'] == 'info':
                    out.write('[*] {0}\n'.format(entry['data']))
                elif entry['type'] == 'item':
                    out.write('  [-] {0}\n'.format(entry['data']))
                elif entry['type'] == 'warning':
                    out.write('[!] {0}\n'.format(entry['data']))
                elif entry['type'] == 'error':
                    out.write('[!] {0}\n'.format(entry['data']))
                elif entry['type'] == 'success':
                    out.write('[+] {0}\n'.format(entry['data']))
                elif entry['type'] == 'table':
                    out.write(str(table(
                        header=entry['data']['header'],
                        rows=entry['data']['rows']
                    )))
                    out.write('\n')
                else:
                    out.write('{0}\n'.format(entry['data']))
        print_success("Output written to {0}".format(filename))
    else:
        for entry in output:
            if entry['type'] == 'info':
                print_info(entry['data'])
            elif entry['type'] == 'item':
                print_item(entry['data'])
            elif entry['type'] == 'warning':
                print_warning(entry['data'])
            elif entry['type'] == 'error':
                print_error(entry['data'])
            elif entry['type'] == 'success':
                print_success(entry['data'])
            elif entry['type'] == 'table':
                print(table(
                    header=entry['data']['header'],
                    rows=entry['data']['rows']
                ))
            else:
                print(entry['data'])
