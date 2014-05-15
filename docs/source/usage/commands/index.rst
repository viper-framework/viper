========
Commands
========

Open
====

Viper relies on a session to determine on which binary file the user is currently operating on. 
Every command or module will operate against the currently opened file, if it is meant to do so obviously.

A session is opened with the open command:::

    shell > open --help
    usage: open [-h] [-f] [-u] [-t] <target>

    Options:
        --help (-h) Show this help message
        --file (-f) The target is a file
        --url (-u)  The target is a URL
        --tor (-t)  Download the file through Tor

You can also specify a SHA256 or MD5 hash to a previously stored file in order to open a session on it.

::

    example 1 . Open a file from the local machine
    shell > open -f ~/data/malware/misc/poisonivy.exe
    [*] Session opened on /home/nex/data/malware/misc/poisonivy.exe
    shell poisonivy.exe >
    
    example 2 . Open a file from a URL
    shell > open -u http://google.com/malware.exe
    [*] Session opened on /tmp/tmp9S8s8F
    shell tmp9S8s8F >

    example 3. Open a URL using tor
    
When opening a file from URL it is possible to open the Rendered HTML of a page. e.g. open -u http://google.com will result in
the session holding the raw HTML 

Store
=====

There are multiple ways to feed files to Viper's repository. If you have an existing session open, as shown before, you can simply issue a store command:
Viper will store a local copy of the file and switch the session to it.

Additionally you can import entire folders, assign tags, delete original files, etc.:
tags will be explained in more detail later in this document.

::

    shell > store --help
    usage: store [-h] [-d] [-f <path>] [-s <size>] [-y <type>] [-n <name>] [-t]

    Options:
        --help (-h) Show this help message
        --delete (-d)   Delete the original file
        --folder (-f)   Specify a folder to import
        --file-size (-s)    Specify a maximum file size
        --file-type (-y)    Specify a file type pattern
        --file-name (-n)    Specify a file name pattern
        --tags (-t) Specify a list of comma-separated tags
