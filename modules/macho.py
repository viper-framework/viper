# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.



from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    from modules.pymacho.MachO import MachO
    HAVE_MACHO = True
except ImportError:
    HAVE_MACHO = False


class Macho(Module):
    cmd = 'macho'
    description = 'Get Macho OSX Headers'
    authors = ['Alexander J']

    def __init__(self):
        super(Macho, self).__init__()
        #self.parser.add_argument('-i', '--info', action='store_true', help='Show general info')
        self.parser.add_argument('-hd','--headers',action='store_true', help='show informations about header')
        self.parser.add_argument( '-sg','--segments', help='display all segments', action='store_true')
        self.parser.add_argument( '-lc','--load-commands', help='display all load commands', action='store_true')
        self.parser.add_argument( '-a','--all', help='display all', action='store_true')

    def run(self):
        super(Macho, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        if not HAVE_MACHO:
            self.log('error', "Missing dependency")
            return
            
        # List general info
        def macho_headers(m):
            self.log('info', "Headers: ")
            magic="magic : 0x%x %s" % (m.header.magic, "- " + m.header.display_magic())
            self.log('item', magic)
            cputype="cputype : 0x%x %s" % (m.header.cputype, "- " + m.header.display_cputype())
            self.log('item', cputype)
            cpu_subtype="cpusubtype : 0x%s" % (m.header.cpusubtype)
            self.log('item', cpu_subtype)
            filetype="filetype : 0x%x %s" % (m.header.filetype, "- " + m.header.display_filetype())
            self.log('item', filetype)
            ncmds="ncmds : %d" % (m.header.ncmds)
            self.log('item', ncmds)
            sizeofcmds="sizeofcmds : %d bytes" % (m.header.sizeofcmds)
            self.log('item', sizeofcmds)
            flags="flags : 0x%x %s" % (m.header.flags, "- " + ", ".join(m.header.display_flags()))
            self.log('item',flags)
            if m.header.is_64():
                reserved="reserved : 0x%x" % (m.header.reserved)
                self.log('item',reserved)
            
            #self.log('item', "filetype: 0x{0}".format(m.header.display_filetype()))
            #self.log('item', "ncmds: 0x{0}".format(m.header.ncmds))
            
    
        #print all load commands
        #TODO replace display method
        def macho_load_commands(m):
            load_commands=" Load Commands (%d)" % len(m.commands)
            self.log('info', load_commands)
            for lc in m.commands:
                lc.display("\t")
    
        #print all segments
        #TODO replace display method
        def macho_segments(m):
            segments=" Segments (%d)" % len(m.segments)
            self.log('info', segments)
            for segment in m.segments:
                segment.display(before="\t")
        
        
        try:
            m = MachO(__sessions__.current.file.path)
        except Exception as e:
            self.log('error', "No Mach0 file, {0}".format(e))
            return
                
        if self.args is None:
            return
        elif self.args.all:
            macho_headers(m)
            macho_segments(m)
            macho_load_commands(m)   
        elif self.args.headers:
            macho_headers(m)
        elif self.args.segments:
            macho_segments(m)
        elif self.args.load_commands:
            macho_load_commands(m)   
            
