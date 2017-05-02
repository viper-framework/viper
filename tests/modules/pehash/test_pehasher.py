# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.modules.pehash import pehasher


def test_calculate_pehash():
    assert pehasher.calculate_pehash() == ''
