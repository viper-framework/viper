import sys
try:
    import lief
    HAVE_LIEF = True
except:
    HAVE_LIEF = False

if not HAVE_LIEF:
    self.log("error", "Missing dependency, install lief (pip3 install lief)")
    sys.exit(1)

MACHO_HEADER_FLAGS = {
    lief.MachO.HEADER_FLAGS.ALLMODSBOUND            : 'ALLMODSBOUND',
    lief.MachO.HEADER_FLAGS.ALLOW_STACK_EXECUTION   : 'ALLOW_STACK_EXECUTION',
    lief.MachO.HEADER_FLAGS.APP_EXTENSION_SAFE      : 'APP_EXTENSION_SAFE',
    lief.MachO.HEADER_FLAGS.BINDATLOAD              : 'BINDATLOAD',
    lief.MachO.HEADER_FLAGS.BINDS_TO_WEAK           : 'BINDS_TO_WEAK',
    lief.MachO.HEADER_FLAGS.CANONICAL               : 'CANONICAL',
    lief.MachO.HEADER_FLAGS.DEAD_STRIPPABLE_DYLIB   : 'DEAD_STRIPPABLE_DYLIB',
    lief.MachO.HEADER_FLAGS.DYLDLINK                : 'DYLDLINK',
    lief.MachO.HEADER_FLAGS.FORCE_FLAT              : 'FORCE_FLAT',
    lief.MachO.HEADER_FLAGS.INCRLINK                : 'INCRLINK',
    lief.MachO.HEADER_FLAGS.LAZY_INIT               : 'LAZY_INIT',
    lief.MachO.HEADER_FLAGS.NOFIXPREBINDING         : 'NOFIXPREBINDING',
    lief.MachO.HEADER_FLAGS.NOMULTIDEFS             : 'NOMULTIDEFS ',
    lief.MachO.HEADER_FLAGS.NOUNDEFS                : 'NOUNDEFS ',
    lief.MachO.HEADER_FLAGS.NO_HEAP_EXECUTION       : 'NO_HEAP_EXECUTION',
    lief.MachO.HEADER_FLAGS.NO_REEXPORTED_DYLIBS    : 'NO_REEXPORTED_DYLIBS',
    lief.MachO.HEADER_FLAGS.PIE                     : 'PIE ',
    lief.MachO.HEADER_FLAGS.PREBINDABLE             : 'PREBINDABLE ',
    lief.MachO.HEADER_FLAGS.PREBOUND                : 'PREBOUND ',
    lief.MachO.HEADER_FLAGS.ROOT_SAFE               : 'ROOT_SAFE',
    lief.MachO.HEADER_FLAGS.SETUID_SAFE             : 'SETUID_SAFE',
    lief.MachO.HEADER_FLAGS.SPLIT_SEGS              : 'SPLIT_SEGS',
    lief.MachO.HEADER_FLAGS.SUBSECTIONS_VIA_SYMBOLS : 'SUBSECTIONS_VIA_SYMBOLS',
    lief.MachO.HEADER_FLAGS.TWOLEVEL                : 'TWOLEVEL ',
    lief.MachO.HEADER_FLAGS.WEAK_DEFINES            : 'WEAK_DEFINES',
    lief.MachO.HEADER_FLAGS.HAS_TLV_DESCRIPTORS     : 'HAS_TLV_DESCRIPTORS'
}

MACHO_FILE_TYPES = {
    lief.MachO.FILE_TYPES.BUNDLE        :   'BUNDLE',
    lief.MachO.FILE_TYPES.CORE          :   'CORE',
    lief.MachO.FILE_TYPES.DSYM          :   'DSYM',
    lief.MachO.FILE_TYPES.DYLIB         :   'DYLIB',
    lief.MachO.FILE_TYPES.DYLIB_STUB    :   'DYLIB_STUB',
    lief.MachO.FILE_TYPES.DYLINKER      :   'DYLINKER',
    lief.MachO.FILE_TYPES.EXECUTE       :   'EXECUTE',
    lief.MachO.FILE_TYPES.FVMLIB        :   'FVMLIB',
    lief.MachO.FILE_TYPES.KEXT_BUNDLE   :   'KEXT_BUNDLE',
    lief.MachO.FILE_TYPES.OBJECT        :   'OBJECT',
    lief.MachO.FILE_TYPES.PRELOAD       :   'PRELOAD'
}

MACHO_CPU_TYPES = {
    lief.MachO.CPU_TYPES.ANY        :   'ANY',
    lief.MachO.CPU_TYPES.ARM        :   'ARM',
    lief.MachO.CPU_TYPES.ARM64      :   'ARM64',
    lief.MachO.CPU_TYPES.MC98000    :   'MC98000',
    lief.MachO.CPU_TYPES.POWERPC    :   'POWERPC',
    lief.MachO.CPU_TYPES.POWERPC64  :   'POWERPC64',
    lief.MachO.CPU_TYPES.SPARC      :   'SPARC',
    lief.MachO.CPU_TYPES.x86        :   'x86',
    lief.MachO.CPU_TYPES.x86_64     :   'x86_64'
}

MACHO_LOAD_COMMAND_TYPES = {
    lief.MachO.LOAD_COMMAND_TYPES.CODE_SIGNATURE            :   'CODE_SIGNATURE',
    lief.MachO.LOAD_COMMAND_TYPES.DATA_IN_CODE              :   'DATA_IN_CODE',
    lief.MachO.LOAD_COMMAND_TYPES.DYLD_ENVIRONMENT          :   'DYLD_ENVIRONMENT',
    lief.MachO.LOAD_COMMAND_TYPES.DYLD_INFO                 :   'DYLD_INFO',
    lief.MachO.LOAD_COMMAND_TYPES.DYLD_INFO_ONLY            :   'DYLD_INFO_ONLY',
    lief.MachO.LOAD_COMMAND_TYPES.DYLIB_CODE_SIGN_DRS       :   'DYLIB_CODE_SIGN_DRC',
    lief.MachO.LOAD_COMMAND_TYPES.DYSYMTAB                  :   'DYSYMTAB',
    lief.MachO.LOAD_COMMAND_TYPES.ENCRYPTION_INFO           :   'ENCRYPTION_INFO',
    lief.MachO.LOAD_COMMAND_TYPES.ENCRYPTION_INFO_64        :   'ENCRYPTION_INFO_64',
    lief.MachO.LOAD_COMMAND_TYPES.FUNCTION_STARTS           :   'FUNCTION_STARTS',
    lief.MachO.LOAD_COMMAND_TYPES.FVMFILE                   :   'FVMFILE',
    lief.MachO.LOAD_COMMAND_TYPES.IDENT                     :   'IDENT',
    lief.MachO.LOAD_COMMAND_TYPES.IDFVMLIB                  :   'IDFVMLAB',
    lief.MachO.LOAD_COMMAND_TYPES.ID_DYLIB                  :   'ID_DYLIB',
    lief.MachO.LOAD_COMMAND_TYPES.ID_DYLINKER               :   'ID_DYLINKER',
    lief.MachO.LOAD_COMMAND_TYPES.LAZY_LOAD_DYLIB           :   'LAZY_LOAD_DYLIB',
    lief.MachO.LOAD_COMMAND_TYPES.LINKER_OPTIMIZATION_HINT  :   'LINKER_OPTIMIZATION_HINT',
    lief.MachO.LOAD_COMMAND_TYPES.LINKER_OPTION             :   'LINKER_OPTION',
    lief.MachO.LOAD_COMMAND_TYPES.LOADFVMLIB                :   'LOADFVMLIB',
    lief.MachO.LOAD_COMMAND_TYPES.LOAD_DYLIB                :   'LOAD_DYLIB',
    lief.MachO.LOAD_COMMAND_TYPES.LOAD_DYLINKER             :   'LOAD_DYLINKER',
    lief.MachO.LOAD_COMMAND_TYPES.LOAD_UPWARD_DYLIB         :   'LOAD_UPWARD_DYLIB',
    lief.MachO.LOAD_COMMAND_TYPES.LOAD_WEAK_DYLIB           :   'LOAD_WEAK_DYLIB',
    lief.MachO.LOAD_COMMAND_TYPES.MAIN                      :   'MAIN',
    lief.MachO.LOAD_COMMAND_TYPES.PREBIND_CKSUM             :   'PREBIND_CKSUM',
    lief.MachO.LOAD_COMMAND_TYPES.PREBOUND_DYLIB            :   'PREBOUND_DYLIB',
    lief.MachO.LOAD_COMMAND_TYPES.PREPAGE                   :   'PREPAGE',
    lief.MachO.LOAD_COMMAND_TYPES.REEXPORT_DYLIB            :   'REEXPORT_DYLIB',
    lief.MachO.LOAD_COMMAND_TYPES.ROUTINES                  :   'ROUTINES',
    lief.MachO.LOAD_COMMAND_TYPES.ROUTINES_64               :   'ROUTINES_64',
    lief.MachO.LOAD_COMMAND_TYPES.RPATH                     :   'RPATH',
    lief.MachO.LOAD_COMMAND_TYPES.SEGMENT                   :   'SEGMENT',
    lief.MachO.LOAD_COMMAND_TYPES.SEGMENT_64                :   'SEGMENT_64',
    lief.MachO.LOAD_COMMAND_TYPES.SEGMENT_SPLIT_INFO        :   'SEGMENT_SPLIT_INFO',
    lief.MachO.LOAD_COMMAND_TYPES.SOURCE_VERSION            :   'SOURCE_VERSION',
    lief.MachO.LOAD_COMMAND_TYPES.SUB_CLIENT                :   'SUB_CLIENT',
    lief.MachO.LOAD_COMMAND_TYPES.SUB_FRAMEWORK             :   'SUB_FRAMEWORK',
    lief.MachO.LOAD_COMMAND_TYPES.SUB_LIBRARY               :   'SUB_LIBRARY',
    lief.MachO.LOAD_COMMAND_TYPES.SUB_UMBRELLA              :   'SUB_UMBRELLA',
    lief.MachO.LOAD_COMMAND_TYPES.SYMSEG                    :   'SYMSEG',
    lief.MachO.LOAD_COMMAND_TYPES.SYMTAB                    :   'SYMTAB',
    lief.MachO.LOAD_COMMAND_TYPES.THREAD                    :   'THRAD',
    lief.MachO.LOAD_COMMAND_TYPES.TWOLEVEL_HINTS            :   'TWOLEVEL_HINTS',
    lief.MachO.LOAD_COMMAND_TYPES.UNIXTHREAD                :   'UNIXTHREAD',
    lief.MachO.LOAD_COMMAND_TYPES.UUID                      :   'UUID',
    lief.MachO.LOAD_COMMAND_TYPES.VERSION_MIN_IPHONEOS      :   'VERSION_MIN_IPHONEOS',
    lief.MachO.LOAD_COMMAND_TYPES.VERSION_MIN_MACOSX        :   'VERSION_MIN_MACOSX',
    lief.MachO.LOAD_COMMAND_TYPES.VERSION_MIN_TVOS          :   'VERSION_MIN_TVOS',
    lief.MachO.LOAD_COMMAND_TYPES.VERSION_MIN_WATCHOS       :   'VERSION_MIN_WATCHOS'
}
