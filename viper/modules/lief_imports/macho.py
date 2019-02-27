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
