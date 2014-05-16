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
