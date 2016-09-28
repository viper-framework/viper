from viper.common.abstracts import Module
from viper.core.session import __sessions__


class SurfaceAnalysis(Module):
    cmd = 'surface'
    description = 'Perform Surface Analysis'
    authors = ['Christophe Vandeplas']

    def __init__(self):
        super(SurfaceAnalysis, self).__init__()

    def run(self):
        super(SurfaceAnalysis, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        try:
            self.log('info', "The report is:")
            self.log('info', __sessions__.current.file.path)
        except OSError:
            self.log('error', "Something is wrong, but what? I don't know.")
            return

        ####
        # Generic
        # - OK hashes (incl ssdeep)
        # - OK file size
        # - OK exif
        # - OK VT lookup
        # - YARA
        # - OK upload to metascan
        # - OK output of file command
        # - bit9
        # For EXE
        # - string - ip/hostnames
        # - pe:  peid, compiletime, language, security, sections, exports, imports
        # - send to sandbox
        # - search for specific string types:  pdb, ...
        # For PDF
        #
        # For DOC
        #

        ####
        self.log('table', dict(
            header=['Key', 'Value'],
            rows=[
                ['Name', __sessions__.current.file.name],
                ['Tags', __sessions__.current.file.tags],
                ['Size', __sessions__.current.file.size],
                ['Type', __sessions__.current.file.type],
                ['Mime', __sessions__.current.file.mime],
                ['MD5', __sessions__.current.file.md5],
                ['SHA1', __sessions__.current.file.sha1],
                ['SHA256', __sessions__.current.file.sha256],
                # ['SHA512', __sessions__.current.file.sha512],
                ['SSdeep', __sessions__.current.file.ssdeep],
                # ['CRC32', __sessions__.current.file.crc32],
                # ['Parent', __sessions__.current.file.parent],
                # ['Children', __sessions__.current.file.children]
            ]))

        from viper.modules import virustotal
        print("")
        print("VirusTotal")
        print("----------")
        m_vt = virustotal.VirusTotal()
        m_vt.command_line.append('-v')
        m_vt.run()
        del m_vt.command_line[:]

        from viper.modules import metascan
        print("")
        print("Metascan")
        print("----------")
        m_m = metascan.Metascan()
        m_m.command_line.append('-v')
        m_m.run()
        del m_m.command_line[:]

        from viper.modules import pe
        print("")
        print("PE information")
        print("--------------")
        m_pe = pe.PE()
        m_pe.command_line.append('peid')
        m_pe.run()
        del m_pe.command_line[:]

        m_pe.command_line.append('compiletime')
        m_pe.run()
        del m_pe.command_line[:]

        m_pe.command_line.append('language')
        m_pe.run()
        del m_pe.command_line[:]

        m_pe.command_line.append('security')
        m_pe.command_line.append('-c')
        m_pe.run()
        del m_pe.command_line[:]

        m_pe.command_line.append('sections')
        m_pe.run()
        del m_pe.command_line[:]

        m_pe.command_line.append('exports')
        m_pe.run()
        del m_pe.command_line[:]

        m_pe.command_line.append('imports')
        self.log('info', "Imports:")
        m_pe.run()
        del m_pe.command_line[:]

        from viper.modules import strings
        print("")
        print("Strings - IP")
        print("------------")
        m_strings = strings.Strings()
        m_strings.command_line.append('-H')
        m_strings.run()
        del m_strings.command_line[:]

        from viper.modules import exif
        m_exif = exif.Exif()
        print("")
        print("Exif")
        print("----")
        m_exif.run()
        del m_exif.command_line[:]

        print("")
        print("Strings - All")
        print("-------------")
        m_strings = strings.Strings()
        m_strings.command_line.append('-a')
        m_strings.run()
        del m_strings.command_line[:]

        #
        # Switch based on the file type
        # 
        # application/x-dosexec
        #rows = []
        #for key, value in metadata.items():
        #    rows.append([key, value])

        #rows = sorted(rows, key=lambda entry: entry[0])

        #self.log('info', "MetaData:")
        #self.log('table', dict(header=['Key', 'Value'], rows=rows))

