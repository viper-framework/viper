# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import math
import getopt
import string
import hashlib
from collections import Counter

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

class HTMLParse(Module):
    cmd = 'html'
    description = 'Parse html files and extract content'
    authors = ['Kevin Breen', 'nex']

    def __init__(self):
        self.soup = None

    def string_clean(self, value):
        try:
            value = filter(lambda x: x in string.printable, value)
            return re.sub('[\n\t\r]', '', value)
        except:
            return value

    def shannon_entropy(self, s):
        s = str(s)
        p, lns = Counter(s), float(len(s))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

    def dump_output(self, stream, out_dir, out_type):
        stream = str(stream)
        # TODO: Change this to a folder per type.
        md5 = hashlib.md5(stream).hexdigest()

        out_name = "HTML_{0}_{1}".format(md5, out_type)
        out_path = os.path.join(out_dir, out_name)

        with open(out_path, 'w') as out:
            out.write(stream)

    def parse_scripts(self):
        scripts = []
        script_content = []
        for script in self.soup.find_all('script'):
            script_type = script.get('type')
            script_src = script.get('src')
            content = script.string
            script_content.append(content)
            script_entropy = self.shannon_entropy(script_content)
            scripts.append([
                script_type,
                script_src,
                script_entropy
            ])

        return scripts, script_content

    def parse_hrefs(self):
        links = []
        for link in self.soup.find_all('a'):
            url = link.get('href')
            text = link.string
            links.append([url, text])

        return links
        
    def parse_iframes(self):
        # TODO: soup the iframe contents and look for hrefs.
        iframes = []
        frame_content = []
        for frame in self.soup.find_all('iframe'):
            src = frame.get('src')
            content = frame
            entropy = self.shannon_entropy(content)
            size = "{0}x{1}".format(frame.get('width'), frame.get('height'))
            # Because None can be misleading when no width or height is specified for the ifame
            size = size.replace('NonexNone','Not Specified')
            iframes.append([src, size, entropy])
            frame_content.append(content)
        return iframes, frame_content
            
    def parse_embedded(self):
        # Java Applets
        java = []
        flash = []
        for applet in self.soup.find_all('applet'):
            archive = applet.get('archive')
            code = applet.get('code')
            java.append([archive, code])
        # flash
        for embed in self.soup.find_all('embed'):
            src = embed.get('src')
            flash.append([src])
        for obj in self.soup.find_all('object'):
            data = obj.get('data')
            flash.append([data])
        return java, flash
            

    def parse_images(self):
        images = []
        for image in self.soup.find_all('img'):
            img_src = image.get('src')
            img_alt = image.get('alt')
            images.append([img_src, img_alt])
        return images

    def run(self):
        def usage():
            self.log('', "usage: html [-hslfeid]")
            self.log('', "The --dump option is availiable for iframes scripts and images")
            self.log('', "If you use --dump with images an http request will be executed to fetch each image")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--script (-s)\tExtract all script tags")
            self.log('', "\t--links (-l)\tShow all links")
            self.log('', "\t--iframe (-f)\tShow all iframes")
            self.log('', "\t--embed (-e)\tShow all embedded files")
            self.log('', "\t--images (-i)\tExtract all images")
            self.log('', "\t--dump (-d)\tDump all outputs to files")
                
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        try:
            opts, argv = getopt.getopt(self.args, 'hslfeid:', ['help', 'script', 'links', 'frame', 'embed', 'images', 'dump='])
        except getopt.GetoptError as e:
            self.log('', e)
            return

        try:
            html_data = open(__sessions__.current.file.path).read()
            self.soup = BeautifulSoup(html_data)
        except Exception as e:
            self.log('error', "Something went wrong: {0}".format(e))
            return

        # Check first if the --dump option has been enabled.
        arg_dump = None
        for opt, value in opts:
            if opt in ('-d', '--dump'):
                arg_dump = value
        
        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--script'):
                scripts, script_content = self.parse_scripts()
                if arg_dump:
                    self.log('info', "Dumping Output to {0}".format(arg_dump))
                    for s in script_content:
                        self.dump_output(s, arg_dump, 'Scripts')
                    return
                else:
                    self.log('info', "Scripts:")
                    self.log('table', dict(header=['Type', 'Source', 'Entropy'], rows=scripts))
                return
            elif opt in ('-l' '--links'):
                links = self.parse_hrefs()
                self.log('info', "Links")
                self.log('info', "Target \t Text")
                for link in links:
                    self.log('item', "{0}\t {1}".format(link[0], self.string_clean(link[1])))
                return
                
            # iFrames
            elif opt in ('-f', '--frame'):
                frames, frame_content = self.parse_iframes()
                if arg_dump:
                    self.log('info', "Dumping Output to {0}".format(arg_dump))
                    for f in frame_content:
                        self.dump_output(f, arg_dump, 'iframe')
                    return
                else:
                    self.log('info', "IFrames")
                    self.log('table', dict(header=['Source','Size','Entropy'], rows=frames))
                return
                
            # Images
            elif opt in ('-i','--images'):
                images = self.parse_images()
                if arg_dump:
                    self.log('info', "Dumping Images to {0}".format(arg_dump))
                    self.log('error', "Not Implemented Yet")
                    # this will need an extra http request to download the images
                    return
                else:
                    self.log('info', "Images")
                    self.log('table', dict(header=['Source','Alt',], rows=images))
                return

            # Embedded
            elif opt in ('-e','--embed'):
                java, flash = self.parse_embedded()
                if arg_dump:
                    self.log('info', "Dumping Embedded Items to {0}".format(arg_dump))
                    self.log('error', "Not Implemented Yet")
                    # this will need an extra http request to download the images
                    return
                else:
                    if len(java) > 0:
                        self.log('info', "Embedded Java Objects")
                        self.log('table', dict(header=['Archive','Code',], rows=java))
                        print ""
                    if len(flash) > 0:
                        self.log('info', "Embedded Flash Objects")
                        self.log('table', dict(header=['Swf Src'], rows=flash))
                return

        help()
