# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

try:
    from terminaltables import AsciiTable
    HAVE_TERMTAB = True
except ImportError:
    HAVE_TERMTAB = False

import textwrap
import six
import sys

from viper.common.colors import cyan, yellow, red, green, bold


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
    if not HAVE_TERMTAB:
        print_error("Missing dependency, install terminaltables (`pip install terminaltables`)")
        return

    # TODO: Refactor this function, it is some serious ugly code.

    content = []
    for l in [header] + rows:
        to_append = []
        for a in l:
            if isinstance(a, bytes):
                if sys.version_info < (3, 4):
                    a = a.decode('utf-8', 'ignore')
                else:
                    a = a.decode('utf-8', 'backslashreplace')
            if not isinstance(a, six.text_type):
                a = six.text_type(a)
            to_append.append(a.replace('\t', '  ').replace('\v', '\\v'))
        content.append(to_append)
    t = AsciiTable(content)
    if not t.ok:
        t.inner_row_border = True
        longest_col = t.column_widths.index(max(t.column_widths))
        max_length_col = t.column_max_width(longest_col)
        if max_length_col > 0:
            for i, content in enumerate(t.table_data):
                if len(content[longest_col]) > max_length_col:
                    temp = ''
                    for l in content[longest_col].splitlines():
                        if len(l) > max_length_col:
                            temp += '\n'.join(textwrap.wrap(l, max_length_col)) + '\n'
                        else:
                            temp += l + '\n'
                        content[longest_col] = temp.strip()
                t.table_data[i] = content

    return t.table


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
