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
