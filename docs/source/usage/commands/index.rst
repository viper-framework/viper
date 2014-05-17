========
Commands
========

Commands are core functions that exist within viper. These provide methods to load and store files and sessions.
It is also contains functiosn that can interact with the Database such as tagging files. 

Clear
=====

Clear simply clears the terminal window

close
=====

This command simply closes the open session and release any open handles to the file. 

delete
======

This command deletes the file for the active session. It is removed from the binary storage structure, any entries in the DB and finally closes the open session 

find
====

The find command is the primary method for searching data stored in the database

::

    shell > find -h
    usage: find [-h] [-t] <all|latest|name|md5|sha256|tag> <value>

    Options:
        --help (-h) Show this help message
        --tags (-t) List tags

    shell > find tag darkcomet
    +----+------------------------------------------------------------------+-----------------------+----------------------------------+
    | #  | Name                                                             | Mime                  | MD5                              |
    +----+------------------------------------------------------------------+-----------------------+----------------------------------+
    | 1  | VirusShare_3d0c25c95714deed4a7313e0dfc903ca                      | application/x-dosexec | 3d0c25c95714deed4a7313e0dfc903ca |
    | 2  | VirusShare_4c450a434992367d668a4ebaf42c224c                      | application/x-dosexec | 4c450a434992367d668a4ebaf42c224c |
    | 3  | VirusShare_500064addacc7c0956c7d7ff86538027                      | application/x-dosexec | 500064addacc7c0956c7d7ff86538027 |
    | 4  | VirusShare_f8072c5003308e219213671ccc27757a                      | application/x-dosexec | f8072c5003308e219213671ccc27757a |
    | 5  | VirusShare_1d783f4e01ca3010e8159f9d7f794adb                      | application/x-dosexec | 1d783f4e01ca3010e8159f9d7f794adb |
    | 6  | VirusShare_bef0efd2fecf19f0f5a57c63955c342c                      | application/x-dosexec | bef0efd2fecf19f0f5a57c63955c342c |

Info
=====

The Info command displays basic database information on the file that is currently active in the session.

::

    +--------+----------------------------------------------------------------------------------------------------------------------------------+
    | Key    | Value                                                                                                                            |
    +--------+----------------------------------------------------------------------------------------------------------------------------------+
    | Name   | VirusShare_3d0c25c95714deed4a7313e0dfc903ca                                                                                      |
    | Tags   | rat, darkcomet                                                                                                                   |
    | Path   | binaries/2/d/7/e/2d7e58ab6515b28636922261176204c94e772d4e2adbe65296094209dc0294c9                                                |
    | Size   | 740352                                                                                                                           |
    | Type   | PE32 executable (GUI) Intel 80386, for MS Windows                                                                                |
    | Mime   | application/x-dosexec                                                                                                            |
    | MD5    | 3d0c25c95714deed4a7313e0dfc903ca                                                                                                 |
    | SHA1   | da33a41dced7b36441aae9569a5016be18c5ab55                                                                                         |
    | SHA256 | 2d7e58ab6515b28636922261176204c94e772d4e2adbe65296094209dc0294c9                                                                 |
    | SHA512 | 39c60494ca6f91fc9854edc37ddf3f67e6aec18a98b84dfb48701966e1e4c63cd8e77d3b5c7e67f78adf49ea56d68a8d6179a1edb5606e2e86c18dc985e9f361 |
    | SSdeep | 12288:gFLlJnnbWOtz6sVJhvaz1Qc/WdI//vfM4qwrbkniafLo6vUTyl0w/q9jJh:Q3nbWmJVJFwSddIXvfhqbiaxvRxq9X                                  |
    | CRC32  | 26E576F5                                                                                                                         |
    +--------+----------------------------------------------------------------------------------------------------------------------------------+

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

session
=======

This command provides options for switching between active sessions.

::

    shell > session -h
    usage: session [-h] [-l] [-s=session]

    Options:
        --help (-h) Show this help message
        --list (-l) List all existing sessions
        --switch (-s)   Switch to the specified session

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

::

    example 1 . store all files in a dir and add tags
    
    shell > store -f /samples/DarkComet/ -t rat,darkcomet
    [+] Stored file "VirusShare_3d0c25c95714deed4a7313e0dfc903ca" to binaries/2/d/7/e/2d7e58ab6515b28636922261176204c94e772d4e2adbe65296094209dc0294c9
    [+] Stored file "VirusShare_4c450a434992367d668a4ebaf42c224c" to binaries/d/7/f/4/d7f4395ef80195becf028123699888b40ff5095ef369aacfcce3efed04d6d1ea
    [+] Stored file "VirusShare_500064addacc7c0956c7d7ff86538027" to binaries/7/e/a/6/7ea604db9f26d78a20181f850c750137ac590d989e8382b2879c0c0485afd469
    [+] Stored file "VirusShare_f8072c5003308e219213671ccc27757a" to binaries/d/8/f/b/d8fb28afd642c3ef9c9872c60cafcb48bc62b5aaed6dc0224be2a32b72cc6934
    [+] Stored file "VirusShare_1d783f4e01ca3010e8159f9d7f794adb" to binaries/e/0/6/b/e06b952c3e5fb53d5a880001dbcd994dc68676ba85fd41ab34a342cad8c8a8d9
    [+] Stored file "VirusShare_bef0efd2fecf19f0f5a57c63955c342c" to binaries/9/5/6/3/9563698449a9f3976e60b37cef43aa526623e6744f1d0d51f22b25297778047c
