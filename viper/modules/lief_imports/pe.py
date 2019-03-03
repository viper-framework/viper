import sys
try:
    import lief
    HAVE_LIEF = True
except:
    HAVE_LIEF = False

if not HAVE_LIEF:
    self.log("error", "Missing dependency, install lief (pip3 install lief)")
    sys.exit(1)

PE_MACHINE_TYPES = {
    lief.PE.MACHINE_TYPES.AM33      :   'AM33',
    lief.PE.MACHINE_TYPES.AMD64     :   'AMD64',
    lief.PE.MACHINE_TYPES.ARM       :   'ARM',
    lief.PE.MACHINE_TYPES.ARMNT     :   'ARMNT',
    lief.PE.MACHINE_TYPES.EBC       :   'EBC',
    lief.PE.MACHINE_TYPES.I386      :   'I386',
    lief.PE.MACHINE_TYPES.IA64      :   'IA64',
    lief.PE.MACHINE_TYPES.INVALID   :   'INVALID',
    lief.PE.MACHINE_TYPES.M32R      :   'M32R',
    lief.PE.MACHINE_TYPES.MIPS16    :   'MIPS16',
    lief.PE.MACHINE_TYPES.MIPSFPU   :   'MIPSFPU',
    lief.PE.MACHINE_TYPES.MIPSFPU16 :   'MIPSFPU16',
    lief.PE.MACHINE_TYPES.POWERPC   :   'POWERPC',
    lief.PE.MACHINE_TYPES.POWERPCFP :   'POWERPCFP',
    lief.PE.MACHINE_TYPES.R4000     :   'R4000',
    lief.PE.MACHINE_TYPES.SH3       :   'SH3',
    lief.PE.MACHINE_TYPES.SH3DSP    :   'SH3DSP',
    lief.PE.MACHINE_TYPES.SH4       :   'SH4',
    lief.PE.MACHINE_TYPES.SH5       :   'SH5',
    lief.PE.MACHINE_TYPES.THUMB     :   'THUMB',
    lief.PE.MACHINE_TYPES.UNKNOWN   :   'UNKNOWN',
    lief.PE.MACHINE_TYPES.WCEMIPSV2 :   'WCEMIPSV2'
}

PE_EXE_FORMATS = { 
    lief.EXE_FORMATS.ELF     :   'ELF',
    lief.EXE_FORMATS.MACHO   :   'MACHO',
    lief.EXE_FORMATS.PE      :   'PE',
    lief.EXE_FORMATS.UNKNOWN :   'UNKNOWN'
}

PE_TYPE = {
    lief.PE.PE_TYPE.PE32        :   'PE32',
    lief.PE.PE_TYPE.PE32_PLUS   :   'PE32_PLUS'
}

PE_SUBSYSTEMS = {
    lief.PE.SUBSYSTEM.EFI_APPLICATION           : 'EFI_APPLICATION',
    lief.PE.SUBSYSTEM.EFI_BOOT_SERVICE_DRIVER   : 'EFI_BOOT_SERVICE_DRIVER',
    lief.PE.SUBSYSTEM.EFI_ROM                   : 'EFI_ROM',
    lief.PE.SUBSYSTEM.EFI_RUNTIME_DRIVER        : 'EFI_RUNTIME_DRIVER',
    lief.PE.SUBSYSTEM.NATIVE                    : 'NATIVE',
    lief.PE.SUBSYSTEM.NATIVE_WINDOWS            : 'NATIVE_WINDOWS',
    lief.PE.SUBSYSTEM.OS2_CUI                   : 'OS2_CUI',
    lief.PE.SUBSYSTEM.POSIX_CUI                 : 'POSIX_CUI',
    lief.PE.SUBSYSTEM.UNKNOWN                   : 'UNKNOWN',
    lief.PE.SUBSYSTEM.WINDOWS_BOOT_APPLICATION  : 'WINDOWS_BOOT_APPLICATION',
    lief.PE.SUBSYSTEM.WINDOWS_CE_GUI            : 'WINDOWS_CE_GUI',
    lief.PE.SUBSYSTEM.WINDOWS_CUI               : 'WINDOWS_CUI',
    lief.PE.SUBSYSTEM.WINDOWS_GUI               : 'WINDOWS_GUI',
    lief.PE.SUBSYSTEM.XBOX                      : 'XOBX'
}
