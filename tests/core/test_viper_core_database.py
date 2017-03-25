# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.core.database import Tag


class TestTag:
    def test_init(self):
        instance = Tag(tag="eggs")
        assert isinstance(instance, Tag)
        assert instance.__repr__() == "<Tag ('None','eggs'>"
