# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.modules import pe
from viper.common.abstracts import Module


class TestPE:
    def test_init(self):
        instance = pe.PE()
        assert isinstance(instance, Module)
