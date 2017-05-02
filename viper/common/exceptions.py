# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.


class GenericException(Exception):
    def __init__(self, message, level=''):
        self.message = message.strip() + '\n'
        self.level = level.strip()

    def __str__(self):
        return '{}: {}'.format(self.level, self.message)

    def get(self):
        return self.level, self.message


class ArgumentErrorCallback(GenericException):
    pass


class Python2UnsupportedUnicode(GenericException):
    pass
