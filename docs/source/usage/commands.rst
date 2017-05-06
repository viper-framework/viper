========
Commands
========

Viper provides a set of core commands used to interact repositories of files you want to collect. In order to see which commands are available, type ``help``::

    shell > help
    Commands:
    +------------+-----------------------------------------------+
    | Command    | Description                                   |
    +------------+-----------------------------------------------+
    | about      | Show information about this Viper instance    |
    | analysis   | View the stored analysis                      |
    | clear      | Clear the console                             |
    | close      | Close the current session                     |
    | copy       | Copy opened file(s) into another project      |
    | delete     | Delete the opened file                        |
    | exit, quit | Exit Viper                                    |
    | export     | Export the current session to file or zip     |
    | find       | Find a file                                   |
    | help       | Show this help message                        |
    | info       | Show information on the opened file           |
    | new        | Create new file                               |
    | notes      | View, add and edit notes on the opened file   |
    | open       | Open a file                                   |
    | parent     | Add or remove a parent file                   |
    | projects   | List or switch existing projects              |
    | rename     | Rename the file in the database               |
    | sessions   | List or switch sessions                       |
    | stats      | Viper Collection Statistics                   |
    | store      | Store the opened file to the local repository |
    | tags       | Modify tags of the opened file                |
    +----------+-------------------------------------------------+

Following are details for all the currently available commands.


about
=====

The **about** command can be used to display some useful information regarding the Viper instance you are currently running. This includes the versions of both Viper itself and of your Python installation. Additionally the path of the active configuration file is shown::


    viper > about
    +----------------+-------------------------------------------------+
    | About          |                                                 |
    +----------------+-------------------------------------------------+
    | Viper Version  | 1.3-dev                                         |
    | Python Version | 3.4.3                                           |
    | Homepage       | https://viper.li                                |
    | Issue Tracker  | https://github.com/viper-framework/viper/issues |
    +----------------+-------------------------------------------------+
    +--------------------------+------------------------------------------------+
    | Configuration            |                                                |
    +--------------------------+------------------------------------------------+
    | Configuration File       | /home/user/.viper/viper.conf                   |
    | Storage Path             | /home/user/.viper                              |
    | Current Project Database | Engine(sqlite:////home/user/.viper/viper.db)   |
    +--------------------------+------------------------------------------------+


projects
========

As anticipated in the :doc:`concepts` section, Viper provides a way to create multiple **projects** which represent isolated collections of files.
You can create a project by simply specifying a value to the ``--project`` argument at launch of ``viper-cli``.

From within the Viper shell, you can list the existing projects and switch from one to another by simply using the ``projects`` command. Following is the help message::

    usage: projects [-h] [-l] [-s=project]

    Options:
        --help (-h) Show this help message
        --list (-l) List all existing projects
        --switch (-s)   Switch to the specified project

Each project will have its own local file repository, its own ``viper.db`` SQLite database and its own ``.viperhistory`` file, which is used to record the history of commands you entered in the terminal.

For example, this is how to launch Viper with a specific project::

    nex@nex:$ viper-cli --project test1
             _
            (_)
       _   _ _ ____  _____  ____
      | | | | |  _ \| ___ |/ ___)
       \ V /| | |_| | ____| |
        \_/ |_|  __/|_____)_| v1.1
              |_|

    You have 0 files in your test1 repository
    test1 shell >

From within the terminal, you can see which projects exist::

    test1 shell > projects -l
    [*] Projects Available:
    +--------------+--------------------------+---------+
    | Project Name | Creation Time            | Current |
    +--------------+--------------------------+---------+
    | test1        | Sat Jul 12 00:53:06 2014 | Yes     |
    +--------------+--------------------------+---------+

You can eventually switch to a different one::

    test1 shell > projects --switch test2
    [*] Switched to project test2
    test2 shell >

Note that if you specify a name of a project that doesn't exist to the ``--switch`` parameter, Viper will create that project and open it nevertheless.


open
====

As explained in the :doc:`concepts` chapter, Viper supports the concept of **session**, which is an execution context created when a specific file is opened and closed only when requested by the user. In order to create a session, you need to issue an ``open`` command. Following is the help message::

    usage: open [-h] [-f] [-u] [-l] [-t] <target|md5|sha256>

    Options:
        --help (-h) Show this help message
        --file (-f) The target is a file
        --url (-u)  The target is a URL
        --last (-l) Open file from the results of the last find command
        --tor (-t)  Download the file through Tor

    You can also specify a MD5 or SHA256 hash to a previously stored
    file in order to open a session on it.

You can fundamentally open:

    * A file available in the local repository
    * Any file available on the local filesystem
    * Any URL

If you don't specify any option, Viper will interpret the value you provided as an hash it has to look up in the local database, for example::

    shell > open 22f77c113cc6d43d8c12ed3c9fb39825
    [*] Session opened on ~/viper/binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26
    shell poisonivy.exe >

If you want to open a file elsewhere on the filesystem, you need to specify the ``--file`` (or ``-f``) flag::

    shell > open -f /tmp/poisonivy.exe
    [*] Session opened on /tmp/poisonivy.exe

If you want to open an URL you can use the ``--url`` flag::

    shell > open --url http://malicious.tld/path/to/file.exe
    [*] Session opened on /tmp/tmpcuIOIj
    shell tmpcuIOIj >

If you have Tor running, you can fetch the file through it by additionally specifying ``--tor``.

Through the ``open`` command you can also directly open one of the entries from the results of the last executed ``find`` command, for example::

    shell > find all
    +---+---------------+-----------------------+----------------------------------+
    | # | Name          | Mime                  | MD5                              |
    +---+---------------+-----------------------+----------------------------------+
    | 1 | poisonivy.exe | application/x-dosexec | 22f77c113cc6d43d8c12ed3c9fb39825 |
    +---+---------------+-----------------------+----------------------------------+
    shell > open --last 1
    [*] Session opened on ~/viper/binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26
    shell poisonivy.exe >


sessions
========

You can see which sessions are currently active and eventually switch from one to another through the ``sessions`` command. Following is the help message::

    usage: sessions [-h] [-l] [-s=session]

    Options:
        --help (-h) Show this help message
        --list (-l) List all existing sessions
        --switch (-s)   Switch to the specified session

An example of execution is the following::

    shell poisonivy.exe > sessions --list
    [*] Opened Sessions:
    +---+---------------+----------------------------------+---------------------+---------+
    | # | Name          | MD5                              | Created At          | Current |
    +---+---------------+----------------------------------+---------------------+---------+
    | 1 | poisonivy.exe | 22f77c113cc6d43d8c12ed3c9fb39825 | 2014-07-12 01:36:14 | Yes     |
    | 2 | zeus.exe      | 9b2de8b062a5538d2a126ba93835d1e9 | 2014-07-12 01:36:19 |         |
    | 3 | darkcomet.exe | 9f2520a3056543d49bb0f822d85ce5dd | 2014-07-12 01:36:23 |         |
    +---+---------------+----------------------------------+---------------------+---------+
    shell poisonivy.exe > sessions --switch 2
    [*] Switched to session #2 on ~/viper/binaries/6/7/6/a/676a818365c573e236245e8182db87ba1bc021c5d8ee7443b9f673f26e7fd7d1
    shell zeus.exe >


export
======

The ``export`` command is used to export the currently opened file to the target path or archive name. You can zip up the file in a new archive too::

    usage: export [-h] [-z] <path or archive name>

    Options:
        --help (-h) Show this help message
        --zip (-z)  Export session in a zip archive


close
=====

This command simply abandon a session that was previously opened. Note that the session will actually remain available in case you want to re-open it later.


store
=====

The ``store`` command is used to store the currently opened file to the local repository. There are many options and filters you can apply, as shown in the following help message::

    usage: store [-h] [-d] [-f <path>] [-s <size>] [-y <type>] [-n <name>] [-t]

    Options:
        --help (-h) Show this help message
        --delete (-d)   Delete the original file
        --folder (-f)   Specify a folder to import
        --file-size (-s)    Specify a maximum file size
        --file-type (-y)    Specify a file type pattern
        --file-name (-n)    Specify a file name pattern
        --tags (-t) Specify a list of comma-separated tags

If you specify ``--delete`` it will instruct Viper to delete the original copy of the file you want to store in the local repository, for example::

    shell > open -f /tmp/poisonivy.exe
    [*] Session opened on /tmp/poisonivy.exe
    shell poisonivy.exe > store --delete
    [+] Stored file "poisonivy.exe" to ~/viper/binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26
    [*] Session opened on ~/viper/binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26
    shell poisonivy.exe >

If you want, you can store the content of an entire folder by specifying its path to the ``--folder`` parameter. In case the folder contains a large variety of files, you can filter which ones you're particularly interested in: with ``--file-size`` you can specify a maximum size in bytes, with ``--file-type`` you can specify a pattern of magic file type (e.g. *PE32*) and with ``--file-name`` you can specify a wildcard-enabled pattern to be matched with the file names (e.g. *apt_**).

If you want, you can already specify a list of comma separated tags to apply to all files stored through the given command.

Following is an example::

    shell > store --folder /tmp/malware --file-type PE32 --file-size 10000000 --file-name apt_* --tags apt,trojan


find
====

In order to quickly recover files you previously stored in the local repository, you can use the ``find`` command. Following is its help message::

    usage: find [-h] [-t] <all|latest|name|md5|sha256|tag|note> <value>

    Options:
        --help (-h) Show this help message
        --tags (-t) List tags

This command expects a key and eventually a value. As shown by the help message, these are the available keys:

    * **all**: this will simply return all available files.
    * **latest** *(optional limit value)*: this will return the latest 5 (or whichever limit you specified) files added to the local repository.
    * **name** *(required value)*: this will find files matching the given name pattern (you can use wildcards).
    * **md5** *(required value)*: search by md5 hash.
    * **sha256** *(required value)*: search by sha256 hash.
    * **tag** *(required value)*: search by tag name.
    * **note** *(required value)*: find files that possess notes matching the given pattern.

For example::

    shell > find tag rat
    +---+---------------+-----------------------+----------------------------------+
    | # | Name          | Mime                  | MD5                              |
    +---+---------------+-----------------------+----------------------------------+
    | 1 | poisonivy.exe | application/x-dosexec | 22f77c113cc6d43d8c12ed3c9fb39825 |
    +---+---------------+-----------------------+----------------------------------+


info
====

The ``info`` command will return you some basic information on the file you currently have opened, for example::

    shell poisonivy.exe > info
    +--------+----------------------------------------------------------------------------------------------------------------------------------+
    | Key    | Value                                                                                                                            |
    +--------+----------------------------------------------------------------------------------------------------------------------------------+
    | Name   | poisonivy.exe                                                                                                                    |
    | Tags   | rat, poisonivy                                                                                                                   |
    | Path   | ~/viper/binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26                                        |
    | Size   | 133007                                                                                                                           |
    | Type   | PE32 executable (GUI) Intel 80386, for MS Windows                                                                                |
    | Mime   | application/x-dosexec                                                                                                            |
    | MD5    | 22f77c113cc6d43d8c12ed3c9fb39825                                                                                                 |
    | SHA1   | dd639a7f682e985406256468d6df8a717e77b7f3                                                                                         |
    | SHA256 | 50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26                                                                 |
    | SHA512 | 6743b06e8b243d513457949ad407d80992254c99b9835eb1ed03fbc0e88a062f0bb09bfd4dd9c0d43093b2a5419ecdb689574c2d2b0d72720080acf9af1b0a84 |
    | SSdeep | 3072:I4lRkAehGfzmuqTPryFm8le+ZNX2TpF3Vb:I4lRkAehaKuqT+FDl7NXs7B                                                                  |
    | CRC32  | 4090D32C                                                                                                                         |
    +--------+----------------------------------------------------------------------------------------------------------------------------------+


notes
=====

During an analysis you might want to keep track of your discoveries and results. Instead of having unorganized text files lying around, Viper allows you to create notes directly linked to the relevant files and even search across them.
When you have a file opened, you can add any number of text notes associated to it through the ``notes`` command. This is the help message::

    usage: notes [-h] [-l] [-a] [-e <note id>] [-d <note id>]

    Options:
        --help (-h) Show this help message
        --list (-h) List all notes available for the current file
        --add (-a)  Add a new note to the current file
        --view (-v) View the specified note
        --edit (-e) Edit an existing note
        --delete (-d)   Delete an existing note

As shown in the help message, you can list add a note::

    shell poisonivy.exe > notes --add
    Enter a title for the new note:

Now you should enter a title, when you proceed Viper will open your default editor to edit the body of the note. Once done and the editor is closed, the new note will be stored::

    [*] New note with title "Domains" added to the current file

Now you can see the new note in the list and view its content::

    shell poisonivy.exe > notes --list
    +----+---------+
    | ID | Title   |
    +----+---------+
    | 1  | Domains |
    +----+---------+
    shell poisonivy.exe > notes --view 1
    [*] Title: Domains
    [*] Body:
    - poisonivy.malicious.tld
    - poisonivy2.malicious.tld


tags
====

In order to easily group and identify files, Viper allows you to create one or more tags to be associated with them. This is the help message::

    usage: tags [-h] [-a=tags] [-d=tag]

    Options:
        --help (-h) Show this help message
        --add (-a)  Add tags to the opened file (comma separated)
        --delete (-d)   Delete a tag from the opened file

Once you have a file opened, you can add one ore more tags separated by a comma::

    shell poisonivy.exe > tags --add rat,poisonivy
    [*] Tags added to the currently opened file
    [*] Refreshing session to update attributes...
    [*] Session opened on ~/viper/binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26

Once added, the session will be refreshed so that the new attributes will be visible as you can see from the output of an ``info`` command::

    shell poisonivy.exe > info
    +--------+----------------------------------------------------------------------------------------------------------------------------------+
    | Key    | Value                                                                                                                            |
    +--------+----------------------------------------------------------------------------------------------------------------------------------+
    | Name   | poisonivy.exe                                                                                                                    |
    | Tags   | rat, poisonivy                                                                                                                   |
    | Path   | ~/viper/binaries/5/0/8/5/50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26                                        |
    | Size   | 133007                                                                                                                           |
    | Type   | PE32 executable (GUI) Intel 80386, for MS Windows                                                                                |
    | Mime   | application/x-dosexec                                                                                                            |
    | MD5    | 22f77c113cc6d43d8c12ed3c9fb39825                                                                                                 |
    | SHA1   | dd639a7f682e985406256468d6df8a717e77b7f3                                                                                         |
    | SHA256 | 50855f9321de846f6a02b264e25e4c59983badb912c3c51d8c71fcd517205f26                                                                 |
    | SHA512 | 6743b06e8b243d513457949ad407d80992254c99b9835eb1ed03fbc0e88a062f0bb09bfd4dd9c0d43093b2a5419ecdb689574c2d2b0d72720080acf9af1b0a84 |
    | SSdeep | 3072:I4lRkAehGfzmuqTPryFm8le+ZNX2TpF3Vb:I4lRkAehaKuqT+FDl7NXs7B                                                                  |
    | CRC32  | 4090D32C                                                                                                                         |
    +--------+----------------------------------------------------------------------------------------------------------------------------------+


copy
======

The ``copy`` command let's you copy the opened file into another project. By default the stored analysis results,
notes and tags will also be copied. If the file has children related to it then these will not be copied by default.
Also copying all children (recursively) can be enabled by passing the ``--children`` or ``-c`` flag.

If the ``--delete`` or ``-d`` is passed then the files will be copied to the specified project and then deleted from the
local project::

    viper foo.txt > copy -h
    usage: copy [-h] [-d] [--no-analysis] [--no-notes] [--no-tags] [-c] project

    Copy opened file into another project

    positional arguments:
      project         Project to copy file(s) to

    optional arguments:
      -h, --help      show this help message and exit
      -d, --delete    delete original file(s) after copy ('move')
      --no-analysis   do not copy analysis details
      --no-notes      do not copy notes
      --no-tags       do not copy tags
      -c, --children  also copy all children - if --delete was selected also the
                      children will be deleted from current project after copy


    viper foo.txt > copy -d foobar
    [+] Copied: e2c94230decedbf4174ac3e35c6160a4c9324862c37cf45124920e63627624c1 (foo.txt)
    [*] Deleted: e2c94230decedbf4174ac3e35c6160a4c9324862c37cf45124920e63627624c1
    [+] Successfully copied sample(s)


delete
======

The ``delete`` command you simply remove the currently opened file from the local repository::

    shell poisonivy.exe > delete
    Are you sure you want to delete this binary? Can't be reverted! [y/n] y
    [+] File deleted
    shell >
