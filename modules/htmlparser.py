# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import getopt
from bs4 import BeautifulSoup
import string
import hashlib

# imports for entropy
import math
from collections import Counter

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class HTMLParse(Module):
    cmd = 'html'
    description = 'Parse html files and extract content'
    authors = ['Kevin Breen', 'nex']

    def run(self):
        def usage():
            print("usage: email [-hslfeid]")
            print("The Dump Option is availiable for iframes scripts and images")
            print("If you use dump with images a standard http request will be used to fetch each image")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--script (-s)\tExtract All script tags")
            print("\t--links (-l)\tShow All Links")
            print("\t--iframe (-f)\tShow all Iframes")
            print("\t--embed (-e)\tShow all embedded files")
            print("\t--images (-i)\tExtract all images")
            print("\t--dump (-d)\tDump all Outputs to files")

        def string_clean(value):
            try:
                value = filter(lambda x: x in string.printable, value)
                return re.sub('[\n\t\r]', '', value)
            except:
                return value

        def shannon_entropy(s):
            s = str(s)
            p, lns = Counter(s), float(len(s))
            return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

        def dump_output(stream, out_dir, out_type):
            stream = str(stream)
            # ToDo - Change this to a folder per type
            md5 = hashlib.md5(stream).hexdigest()
            out_name = "{0}_{1}_{2}".format('HTML', md5, out_type)
            out_path = os.path.join(out_dir, out_name)
            with open(out_path, 'w') as out:
                out.write(stream)
            return

        def parse_scripts(soup):
            scripts = []
            script_content = []
            for script in soup.find_all('script'):
                script_type = script.get('type')
                script_src = script.get('src')
                content = script.string
                script_content.append(content)
                script_entropy = shannon_entropy(script_content)
                scripts.append([script_type, script_src, script_entropy])
            return scripts, script_content

        def parse_hrefs(soup):
            links = []
            for link in soup.find_all('a'):
                url = link.get('href')
                text = link.string
                links.append([url, text])
            print links
            return links
            
        def parse_iframes(soup):
            # ToDo - soup the iframe contents and look for hrefs
            iframes = []
            frame_content = []
            for frame in soup.find_all('iframe'):
                src = frame.get('src')
                content = frame
                entropy = shannon_entropy(content)
                size = "{0}x{1}".format(frame.get('width'), frame.get('height'))
                # Because None can be misleading when no width or height is specified for the ifame
                size = size.replace('NonexNone','Not Specified')
                iframes.append([src, size, entropy])
                frame_content.append(content)
            return iframes, frame_content
                
        def parse_embedded(soup):
            # Java Applets
            java = []
            flash = []
            for applet in soup.find_all('applet'):
                archive = applet.get('archive')
                code = applet.get('code')
                java.append([archive, code])
            # flash
            for embed in soup.find_all('embed'):
                src = embed.get('src')
                flash.append([src])
            for obj in soup.find_all('object'):
                data = obj.get('data')
                flash.append([data])
            return java, flash
                

        def parse_images(soup):
            images = []
            for image in soup.find_all('img'):
                img_src = image.get('src')
                img_alt = image.get('alt')
                images.append([img_src, img_alt])
            return images
                
        # Start Here
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        try:
            opts, argv = getopt.getopt(self.args, 'hslfeid:', ['help', 'script', 'links', 'frame', 'embed', 'images', 'dump='])
        except getopt.GetoptError as e:
            print(e)
            return

        # Create a Soup
        try:
            html_data = open(__sessions__.current.file.path).read()
            soup = BeautifulSoup(html_data)
        except:
            print_error("Something went wrong")
            return
            
        # Get Dump Values
        for opt, value in opts:
            if opt in ('-d', '--dump'):
                dump_flag = True
                dump_path = value
            else:
                dump_flag = False
        
        # run the option
        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
                
            # Script Tags
            elif opt in ('-s', '--script'):
                scripts, script_content = parse_scripts(soup)
                if dump_flag:
                    print_info("Dumping Output to {0}".format(dump_path))
                    for s in script_content:
                        dump_output(s, dump_path, 'Scripts')
                    return
                else:
                    print_info("Scripts")
                    print(table(header=['Type', 'Source', 'Entropy'], rows=scripts))
                return
                
            # Links & Hrefs
            elif opt in ('-l' '--links'):
                links = parse_hrefs(soup)
                # table print here with more than a handful of links throws a maximum recursion depth exceeded
                #print(table(header=['URL', 'Text'], rows=links))
                print_info("Links")
                print_info("Target \t Text")
                for link in links:
                    print_item("{0}\t {1}".format(link[0], string_clean(link[1])))
                return
                
            # iFrames
            elif opt in ('-f', '--frame'):
                frames, frame_content = parse_iframes(soup)
                if dump_flag:
                    print_info("Dumping Output to {0}".format(dump_path))
                    for f in frame_content:
                        dump_output(f, dump_path, 'iframe')
                    return
                else:
                    print_info("IFrames")
                    print(table(header=['Source','Size','Entropy'], rows=frames))
                return
                
            # Images
            elif opt in ('-i','--images'):
                images = parse_images(soup)
                if dump_flag:
                    print_info("Dumping Images to {0}".format(dump_path))
                    print_error("Not Implemented Yet")
                    # this will need an extra http request to download the images
                    return
                else:
                    print_info("Images")
                    print(table(header=['Source','Alt',], rows=images))
                return

            # Embedded
            elif opt in ('-e','--embed'):
                java, flash = parse_embedded(soup)
                if dump_flag:
                    print_info("Dumping Embedded Items to {0}".format(dump_path))
                    print_error("Not Implemented Yet")
                    # this will need an extra http request to download the images
                    return
                else:
                    if len(java) > 0:
                        print_info("Embedded Java Objects")
                        print(table(header=['Archive','Code',], rows=java))
                        print ""
                    if len(flash) > 0:
                        print_info("Embedded Flash Objects")
                        print(table(header=['Swf Src'], rows=flash))
                return

        help()
