# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from django import template

register = template.Library()


@register.filter(name='split_children')
def split_children(value, arg=","):
    """ DEPRECATED!  Workaround - database should really provide a list.."""
    return value.split(arg)[:-1]  # remove last element from list (should always be empty)


@register.filter(name='slice_parent')
def slice_parent(value, arg=-64):
    """ DEPRECATED!  Workaround """
    return value[arg:]
