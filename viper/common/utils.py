# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import string
import hashlib
import binascii
import sys

try:
    import magic
except ImportError:
    pass


# The following couple of functions are redundant.
# TODO: find a way to better integrate these generic methods
# with the ones available in the File class.
def get_type(data):
    try:
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(data)
    except Exception:
        try:
            file_type = magic.from_buffer(data)
        except Exception:
            return ''
    finally:
        try:
            ms.close()
        except Exception:
            pass

    return file_type


def get_md5(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()


def string_clean(line):
    try:
        if isinstance(line, bytes):
            line = line.decode('utf-8')
        return ''.join([x for x in line if x in string.printable])
    except Exception:
        return line


def string_clean_hex(line):
    new_line = ''
    for c in line:
        if c in string.printable:
            new_line += c
        else:
            if sys.version_info >= (3, 0):
                new_line += '\\x' + binascii.hexlify(c.encode('utf-8')).decode('utf-8')
            else:
                new_line += '\\x' + c.encode('hex')
    return new_line


# Snippet taken from:
# https://gist.github.com/sbz/1080258
def hexdump(src, length=16, maxlines=None):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c + length]
        if isinstance(chars, str):
            chars = [ord(x) for x in chars]
        hex = ' '.join(["%02x" % x for x in chars])
        printable = ''.join(["%s" % ((x <= 127 and FILTER[x]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))

        if maxlines:
            if len(lines) == maxlines:
                break

    return ''.join(lines)


# Snippet taken from:
# http://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
def convert_size(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.2f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.2f %s%s" % (num, 'Yi', suffix)
