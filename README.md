Viper
=====

This is the repository for an experimental project temporarily code-named Viper.
It's released under BSD 3-Clause license.

[![Build Status](https://travis-ci.org/botherder/viper.png?branch=master)](https://travis-ci.org/botherder/viper)

Concept
-------

The main idea behind this project is to build a framework to store,
classify and investigate binary files of any sort.

In order to analyze binaries of different nature (being a PE32, a PDF document
or an Office document) we have a large number of very diversified and scattered
scripts and tools available on the Internet and developed by numerous parties.

Having a unique framework would both ease the creation of such scripts as well as
facilitate their collection and provide a one-stop place for researchers to refer
to.

This is still a very primitive idea.

Installation
------------

Prerequisites

    apt-get install python python-dev sqlite3
    behind a proxy you might use: git config --global http.proxy $http_proxy

Clone the git repo

    git clone https://github.com/botherder/viper.git

Switch to the newly created folder

    cd viper
    
Install Python dependencies

    pip install -r requirements.txt
    (this might cause some errors depending on your installed software (install the mentioned tools) TODO: list them more deailed
    behind a proxy you might use: pip install -r requirements.txt -–proxy=user:pass@YOURPROXY:1234

Shell
-----

It's operated through a basic terminal interface:

    shell > help
    Commands:
    +---------+-----------------------------------------------+
    | Command | Description                                   |
    +---------+-----------------------------------------------+
    | info    | Show information on the opened file           |
    | help    | Show this help message                        |
    | clear   | Clear the console                             |
    | close   | Close the current session                     |
    | open    | Open a file                                   |
    | find    | Find a file                                   |
    | store   | Store the opened file to the local repository |
    | delete  | Delete the opened file                        |
    +---------+-----------------------------------------------+

    Modules:
    +------------+------------------------------------------------+
    | Command    | Description                                    |
    +------------+------------------------------------------------+
    | fuzzy      | Search for similar files through fuzzy hashing |
    | yara       | Run Yara scan                                  |
    | strings    | Extract strings from file                      |
    | virustotal | Lookup the file on VirusTotal                  |
    | pe         | Extract information from PE32 headers          |
    +------------+------------------------------------------------+

The shell is used to interact with both a number of built-in commands that
are used to populate and query the local repository of binaries.

The first step is populating the repository. To do so, you can open individual
files.
A session will be opened and all following commands and modules will be executed
against the file currently opened (if that's expected by the command's or module's
functionality of course):

    shell > open -f /tmp/poisonivy.exe
    [*] Session opened on /tmp/poisonivy.exe
    shell /tmp/poisonivy.exe > info
    +--------+----------------------------------------------------------------------------------------------------------------------------------+
    | Key    | Value                                                                                                                            |
    +--------+----------------------------------------------------------------------------------------------------------------------------------+
    | Name   | poisonivy.exe                                                                                                                    |
    | Path   | /tmp/poisonivy.exe                                                                                                               |
    | Size   | 133007                                                                                                                           |
    | Type   | PE32 executable (GUI) Intel 80386, for MS Windows                                                                                |
    | MD5    | 22f77c113cc6d43d8c12ed3c9fb39825                                                                                                 |
    | SHA1   | dd639a7f682e985406256468d6df8a717e77b7f3                                                                                         |
    | SHA256 | 50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26                                                                 |
    | SHA512 | 6743b06e8b243d513457949ad407d80992254c99b9835eb1ed03fbc0e88a062f0bb09bfd4dd9c0d43093b2a5419ecdb689574c2d2b0d72720080acf9af1b0a84 |
    | SSdeep | 3072:I4lRkAehGfzmuqTPryFm8le+ZNX2TpF3Vb:I4lRkAehaKuqT+FDl7NXs7B                                                                  |
    | CRC32  | 4090D32C                                                                                                                         |
    +--------+----------------------------------------------------------------------------------------------------------------------------------+

Once opened, you can store the file locally. The session will be switched to the
local copy of the stored file:

    shell /tmp/poisonivy.exe > store
    [+] DONE: Stored to: binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26
    [*] Session opened on binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26
    shell binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26 > 

At this point, modules can be executed against the stored file:

    shell binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26 > pe resources
    +---------------+---------+-------+------------------------------------------------------+--------------+--------------------+
    | Name          | Offset  | Size  | File Type                                            | Language     | Sublanguage        |
    +---------------+---------+-------+------------------------------------------------------+--------------+--------------------+
    | RT_BITMAP     | 0x276f0 | 0xbb6 | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_ICON       | 0x26490 | 0x128 | GLS_BINARY_LSB_FIRST                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_ICON       | 0x265b8 | 0x568 | GLS_BINARY_LSB_FIRST                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_ICON       | 0x26b20 | 0x2e8 | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_ICON       | 0x26e08 | 0x8a8 | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_DIALOG     | 0x28b98 | 0x286 | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_DIALOG     | 0x28968 | 0x13a | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_DIALOG     | 0x28aa8 | 0xec  | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_DIALOG     | 0x28838 | 0x12e | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_DIALOG     | 0x28500 | 0x338 | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_DIALOG     | 0x282a8 | 0x252 | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_STRING     | 0x293d8 | 0x22c | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_STRING     | 0x29608 | 0x3ce | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_STRING     | 0x299d8 | 0x212 | Hitachi SH big-endian COFF object, not stripped      | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_STRING     | 0x29bf0 | 0x308 | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_STRING     | 0x29ef8 | 0x17c | data                                                 | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_GROUP_ICON | 0x276b0 | 0x3e  | MS Windows icon resource - 4 icons, 16x16, 16-colors | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    | RT_MANIFEST   | 0x28e20 | 0x5b8 | XML document text                                    | LANG_ENGLISH | SUBLANG_ENGLISH_US |
    +---------------+---------+-------+------------------------------------------------------+--------------+--------------------+

As well as normal bash commands if prefixed with an exclamation mark:

    shell binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26 > !hexdump -C $self | head -n5
    00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
    00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
    00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    00000030  00 00 00 00 00 00 00 00  00 00 00 00 e8 00 00 00  |................|
    00000040  0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |........!..L.!Th|
   The $self placeholder will be replaced with the path to the file currently opened.

API
-----
You can interact with your repository with the provided REST API.


To start the webapi

    `./api.py
    Bottle v0.12.7 server starting up (using WSGIRefServer())...
    Listening on http://localhost:8080/
    Hit Ctrl-C to quit.`

All your requests to the API will be shown in the console:

    `127.0.0.1 - - [13/May/2014 21:47:11] "GET /test HTTP/1.1" 200 25`


Test the API

    $ curl http://yourdomain.tld:8080/test
    will return
    {
    "message": "test"
    }

Submit a sample:

    `$ curl -F file=@/foo/bar/file -F tags=foo,bar http://yourdomain.tld:8080/file/add`

Retrieve a sample:

    `$ curl http://yourdomain.tld:8080/file/get/<sha256> > sample.exe`

Find a sample by MD5:

    `$ curl -F md5=<md5> http://yourdomain.tld:8080/file/find`

List existing tags:

    `$ curl http://yourdomain.tld:8080/tags/list`

Display latest 5 md5 hashes

    $curl http://yourdomain.tld:8080/file/latest_md5

More docu is available at:
https://nex.sx/blog/2014-03-26-introducing-viper.html




