# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
from datetime import datetime

import pytest
from tests.conftest import FIXTURE_DIR

from viper.modules import lief
from viper.common.abstracts import Module
from viper.common.abstracts import ArgumentErrorCallback

from viper.core.session import __sessions__

class TestLIEF:
    def test_init(self):
        instance = lief.Lief()
        assert isinstance(instance, lief.Lief)
        assert isinstance(instance, Module)

    def test(self, capsys):
        instance = lief.Lief()
        instance.set_commandline(["elf"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*No open session.*", out)

    def test_args_exception(self):
        instance = lief.Lief()

        with pytest.raises(ArgumentErrorCallback) as excinfo:
            instance.parser.parse_args(["-h"])
        excinfo.match(r".*extract information from ELF, PE, MachO, DEX, OAT, ART and VDEX.*")

    def test_run_help(self, capsys):
        instance = lief.Lief()
        instance.set_commandline(["--help"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_short_help(self, capsys):
        instance = lief.Lief()
        instance.set_commandline(["-h"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r"^usage:.*", out)

    def test_run_invalid_option(self, capsys):
        instance = lief.Lief()
        instance.set_commandline(["invalid"])

        instance.run()
        out, err = capsys.readouterr()
        assert re.search(r".*argument subname: invalid choice.*", out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Sections :.*"),
    ])
    def test_sections_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--sections"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*MachO sections :.*"),
    ])
    def test_sections_macho(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--sections"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*PE sections :.*"),
    ])
    def test_sections_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--sections"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Sections :.*"),
    ])
    def test_sections_oat(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--sections"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Segments :.*"),
    ])
    def test_segments_oat(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--segments"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Segments :.*"),
    ])
    def test_segments_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--segments"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*MachO segments :.*"),
    ])
    def test_segments_macho(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--segments"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Type :.*"),
    ])
    def test_type_oat(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--type"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Type :.*"),
    ])
    def test_type_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--type"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Type :.*"),
    ])
    def test_type_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--type"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*Type :.*"),
    ])
    def test_type_macho(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--type"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*No entrypoint found.*"),
    ])
    def test_entrypoint_oat(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--entrypoint"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Entrypoint :.*"),
    ])
    def test_entrypoint_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--entrypoint"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Entrypoint :.*"),
    ])
    def test_entrypoint_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--entrypoint"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*Entrypoint :.*"),
    ])
    def test_entrypoint_macho(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--entrypoint"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Architecture :.*"),
    ])
    def test_architecture_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--architecture"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Architecture :.*"),
    ])
    def test_architecture_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--architecture"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*Architecture :.*"),
    ])
    def test_architecture_macho(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--architecture"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Entropy :.*"),
    ])
    def test_entropy_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--entropy"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Entropy :.*"),
    ])
    def test_entropy_oat(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--entropy"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Interpreter :.*"),
    ])
    def test_interpreter_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--interpreter"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*No interpreter found.*"),
    ])
    def test_interpreter_oat(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--interpreter"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*No dynamic library found.*"),
    ])
    def test_dynamic_oat(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--dynamic"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Dynamic libraries :.*"),
    ])
    def test_dynamic_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--dynamic"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Dynamic libraries :.*"),
    ])
    def test_dynamic_pe(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--dynamic"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*Dynamic libraries :.*"),
    ])
    def test_dynamic_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--dynamic"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Static and dynamic symbols.*"),
    ])
    def test_symbols_oat(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--symbols"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Static and dynamic symbols.*"),
    ])
    def test_symbols_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--symbols"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*MachO symbols.*"),
    ])
    def test_symbols_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--symbols"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*PE dlls :.*"),
    ])
    def test_dlls_pe(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--dlls"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*PE imports.*"),
    ])
    def test_imports_pe(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--imports"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Imphash :.*"),
    ])
    def test_imphash_pe(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--imphash"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*No GNU hash found.*"),
    ])
    def test_gnu_hash_oat(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--gnu_hash"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*GNU hash :.*"),
    ])
    def test_gnu_hash_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--gnu_hash"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Compilation date :.*"),
    ])
    def test_compiledate_pe(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--compiledate"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*The binary has been stripped.*"),
    ])
    def test_strip_oat(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--strip"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*The binary has been stripped.*"),
    ])
    def test_strip_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--strip"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*File successfully saved.*"),
    ])
    def test_write_elf_1(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--write", "/tmp/test"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Please enter a file name.*"),
    ])
    def test_write_elf_2(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--write", "/tmp/"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Cannot write into folder.*"),
    ])
    def test_write_elf_3(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--write", "/inexistentfolder"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*File already exists.*"),
    ])
    def test_write_elf_4(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--write", "/tmp/test"])
        instance.run()
        os.remove("/tmp/test")
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Notes :.*"),
    ])
    def test_notes_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--notes"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.dex", r".*DEX map items.*"),
    ])
    def test_map_dex(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["dex", "--map"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.art", r".*ART header.*"),
    ])
    def test_header_art(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["art", "--header"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.vdex", r".*VDEX header.*"),
    ])
    def test_header_vdex(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["vdex", "--header"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.dex", r".*DEX header.*"),
    ])
    def test_header_dex(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["dex", "--header"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*OAT header.*"),
    ])
    def test_header_oat(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--header"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*MachO header.*"),
    ])
    def test_header_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--header"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*PE header.*"),
    ])
    def test_header_pe(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--header"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*ELF header.*"),
    ])
    def test_header_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--header"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*MachO code signature :.*"),
    ])
    def test_codesignature_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--codesignature"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Exported functions.*"),
    ])
    def test_exportedfunctions_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--expfunctions"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Exported symbols.*"),
    ])
    def test_exportedsymbols_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--expsymbols"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*No exported symbol found.*"),
    ])
    def test_exportedsymbols_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--expsymbols"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Imported functions.*"),
    ])
    def test_importedfunctions_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--impfunctions"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Imported symbols.*"),
    ])
    def test_importedsymbols_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--impsymbols"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*MachO imported symbols.*"),
    ])
    def test_importedsymbols_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--impsymbols"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample1.macho", r".*Source version :.*"),
    ])
    def test_sourceversion_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--sourceversion"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*No sub-framework found.*"),
    ])
    def test_subFramework_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--subframework"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*Uuid :.*"),
    ])
    def test_uuid_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--uuid"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample1.macho", r".*Data in code :.*"),
    ])
    def test_dataincode_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--dataincode"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample1.macho", r".*Main command :.*"),
    ])
    def test_maincommand_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--maincommand"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.macho", r".*MachO commands :.*"),
    ])
    def test_commands_macho(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["macho", "--commands"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*DOS header.*"),
    ])
    def test_dosheader_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--dosheader"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Data directories.*"),
    ])
    def test_datadirectories_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--datadirectories"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*DOS stub :.*"),
    ])
    def test_dosstub_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--dosstub"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Debug information.*"),
    ])
    def test_debug_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--debug"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample1.pe", r".*Load configuration :.*"),
    ])
    def test_loadconfiguration_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--loadconfiguration"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*No dynamic relocation found.*"),
    ])
    def test_dynamicrelocations_oat(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--dynamicrelocations"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*No object relocation found.*"),
    ])
    def test_objectrelocations_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--objectrelocations"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Relocations :.*"),
    ])
    def test_relocations_elf(soat, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--relocations"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*PE relocations :.*"),
    ])
    def test_relocations_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--relocations"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*PE resources :.*"),
    ])
    def test_resources_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--resources"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample3.pe", r".*PE tls :.*"),
    ])
    def test_tls_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--tls"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Rich header key.*"),
    ])
    def test_richheader_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--richheader"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample2.pe", r".*PE signature :.*"),
    ])
    def test_signature_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--signature"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*PE manifest :.*"),
    ])
    def test_manifest_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--manifest"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Resources types availables.*"),
    ])
    def test_resourcestypes_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--resourcestypes"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*Langs availables.*"),
    ])
    def test_langs_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--langs"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample2.pe", r".*PE icons :.*"),
    ])
    def test_icons_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--icons"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample2.pe", r".*File successfully saved.*"),
    ])
    def test_extracticons_pe_success(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--extracticons", "/tmp/"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample2.pe", r".*File already exists.*"),
    ])
    def test_extracticons_pe_exists(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--extracticons", "/tmp/"])
        instance.run()
        for root, dirs, files in os.walk("/tmp/"):
            for file in filter(lambda x: re.match("^sample2_pe.*.ico$", x), files):
                os.remove(os.path.join(root, file))
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample2.pe", r".*File successfully saved.*"),
    ])
    def test_extracticons_pe_id_success(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--extracticons", "/tmp/", "--id", "1"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample2.pe", r".*File already exists.*"),
    ])
    def test_extracticons_pe_id_exists(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--extracticons", "/tmp/", "--id", "1"])
        instance.run()
        for root, dirs, files in os.walk("/tmp/"):
            for file in filter(lambda x: re.match("^sample2_pe.*.ico$", x), files):
                os.remove(os.path.join(root, file))
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample2.pe", r".*Cannot write into folder.*"),
    ])
    def test_extracticons_pe_error(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--extracticons", "/inexistentfolder"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample2.pe", r".*Icon does not exist.*"),
    ])
    def test_extracticons_pe_id_not_exist(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--extracticons", "/tmp/", "--id", "999999"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.pe", r".*No icon found.*"),
    ])
    def test_extracticons_pe_no_icon_found(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--extracticons", "/tmp/"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample2.pe", r".*Dialog N°.*"),
    ])
    def test_dialogs_pe(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["pe", "--dialogs"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*OAT classes :.*"),
    ])
    def test_classes_oat(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--classes"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.dex", r".*DEX classes :.*"),
    ])
    def test_classes_dex(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["dex", "--classes"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*A class name must be set.*"),
    ])
    def test_methods_oat_no_class(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--methods"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*This class does not exist.*"),
    ])
    def test_methods_oat_inexistent_class(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--methods", "--classname", "inexistentclass"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Information of method.*"),
    ])
    def test_methods_oat_existent_class(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--methods", "--classname", "com.qualcomm.qcrilhook.QmiOemHook"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.dex", r".*Information of method.*"),
    ])
    def test_methods_dex_existent_class(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["dex", "--methods", "--classname", "java.lang.Runtime"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Information of method.*"),
    ])
    def test_methods_oat_existent_class_name(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--methods", "--classname", "com.qualcomm.qcrilhook.QmiOemHook", "--name", "sendQmiMessageSync"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.dex", r".*Information of method.*"),
    ])
    def test_methods_dex_existent_class_name(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["dex", "--methods", "--classname", "java.lang.Runtime", "--name", "exec"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Android version :.*"),
    ])
    def test_androidversion_oat(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--androidversion"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.vdex", r".*Android version :.*"),
    ])
    def test_androidversion_vdex(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["vdex", "--androidversion"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.art", r".*Android version :.*"),
    ])
    def test_androidversion_art(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["art", "--androidversion"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Dex files :.*"),
    ])
    def test_dexfiles_oat(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--dexfiles"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Dynamic entries.*"),
    ])
    def test_dynamicentries_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--dynamicentries"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*Dynamic symbols.*"),
    ])
    def test_dynamicsymbols_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--dynamicsymbols"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.elf", r".*No static symbol found.*"),
    ])
    def test_staticsymbols_elf(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["elf", "--staticsymbols"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Cannot write into folder.*"),
    ])
    def test_extractdexfiles_oat_no_access(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--extractdexfiles", "/inexistentfolder"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)


    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*Dex file does not exist.*"),
    ])
    def test_extractdexfiles_oat_inexistent_name(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--extractdexfiles", "/tmp/", "--name", "inexistentdexfile"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*File successfully saved.*"),
    ])
    def test_extractdexfiles_oat_ok(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--extractdexfiles", "/tmp/"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*File already exist.*"),
    ])
    def test_extractdexfiles_oat_not_ok(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--extractdexfiles", "/tmp/"])
        instance.run()
        for root, dirs, files in os.walk("/tmp/"):
            for file in filter(lambda x: re.match("^0x.*.dex$", x), files):
                os.remove(os.path.join(root, file))
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*File successfully saved.*"),
    ])
    def test_extractdexfiles_oat__name_ok(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--extractdexfiles", "/tmp/", "--name", "classes.dex"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.oat", r".*File already exist.*"),
    ])
    def test_extractdexfiles_oat_name_not_ok(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["oat", "--extractdexfiles", "/tmp/", "--name", "classes.dex"])
        instance.run()
        for root, dirs, files in os.walk("/tmp/"):
            for file in filter(lambda x: re.match("^0x.*.dex$", x), files):
                os.remove(os.path.join(root, file))
        out, err = capsys.readouterr()
        assert re.search(expected, out)

    @pytest.mark.parametrize("filename, expected", [
        ("sample.dex", r".*DEX strings.*"),
    ])
    def test_strings_dex(self, capsys, filename, expected):
        __sessions__.new(os.path.join(FIXTURE_DIR, filename))
        instance = lief.Lief()
        instance.set_commandline(["dex", "--strings"])
        instance.run()
        out, err = capsys.readouterr()
        assert re.search(expected, out)

