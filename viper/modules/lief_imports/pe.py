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

PE_DATA_DIRECTORY = {
    lief.PE.DATA_DIRECTORY.ARCHITECTURE             :    'ARCHITECTURE',
    lief.PE.DATA_DIRECTORY.BASE_RELOCATION_TABLE    :    'BASE_RELOCATION_TABLE',
    lief.PE.DATA_DIRECTORY.BOUND_IMPORT             :    'BOUND_IMPORT',
    lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE        :    'CERTIFICATE_TABLE',
    lief.PE.DATA_DIRECTORY.CLR_RUNTIME_HEADER       :    'CLR_RUNTIME_HEADER',
    lief.PE.DATA_DIRECTORY.DEBUG                    :    'DEBUG',
    lief.PE.DATA_DIRECTORY.DELAY_IMPORT_DESCRIPTOR  :    'DELAY_IMPORT_DESCRIPTOR',
    lief.PE.DATA_DIRECTORY.EXCEPTION_TABLE          :    'EXCEPTION_TABLE',
    lief.PE.DATA_DIRECTORY.EXPORT_TABLE             :    'EXPORT_TABLE',
    lief.PE.DATA_DIRECTORY.GLOBAL_PTR               :    'GLOBAL_PTR',
    lief.PE.DATA_DIRECTORY.IAT                      :    'IAT',
    lief.PE.DATA_DIRECTORY.IMPORT_TABLE             :    'IMPORT_TABLE',
    lief.PE.DATA_DIRECTORY.LOAD_CONFIG_TABLE        :    'LOAD_CONFIG_TABLE',
    lief.PE.DATA_DIRECTORY.RESOURCE_TABLE           :    'RESOURCE_TABLE',
    lief.PE.DATA_DIRECTORY.TLS_TABLE                :    'TLS_TABLE'
}

PE_DEBUG_TYPES = {
    lief.PE.DEBUG_TYPES.BORLAND     :   'BORLAND',
    lief.PE.DEBUG_TYPES.CLSID       :   'CLSID',
    lief.PE.DEBUG_TYPES.CODEVIEW    :   'CODEVIEW',
    lief.PE.DEBUG_TYPES.COFF        :   'COFF',
    lief.PE.DEBUG_TYPES.EXCEPTION   :   'EXCEPTION',
    lief.PE.DEBUG_TYPES.FIXUP       :   'FIXUP',
    lief.PE.DEBUG_TYPES.FPO         :   'FPO',
    lief.PE.DEBUG_TYPES.MISC        :   'MISC',
    lief.PE.DEBUG_TYPES.SRC         :   'SRC',
    lief.PE.DEBUG_TYPES.UNKNOWN     :   'UNKNOWN'
}

PE_CODE_VIEW_SIGNATURES = {
    lief.PE.CODE_VIEW_SIGNATURES.CV_41      :   'CV-41',
    lief.PE.CODE_VIEW_SIGNATURES.CV_50      :   'CV-50',
    lief.PE.CODE_VIEW_SIGNATURES.PDB_20     :   'PDB_20',
    lief.PE.CODE_VIEW_SIGNATURES.PDB_70     :   'PDB-70',
    lief.PE.CODE_VIEW_SIGNATURES.UNKNOWN    :   'UNKNOWN'
}
