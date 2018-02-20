========
Concepts
========

Before proceeding in learning the functioning of each available command and module, you need to understand some fundamental design concept that represent the foundation of Viper itself.

Projects
========

Viper allows you to create and operate on a collection of files. One collection represent one **project**.

You can create as many projects as you want and you can easily switch from one to another. Each project will have its own local repositories of binary files, a SQLite database containing metadata and an history file which contains all the commands you provided through Viper's shell exclusively in the context of the opened project.

In this way you can for example create different workbenches for each malware campaign, malware family or threat actor you're investigating. You can also easily pack up and share the whole project folder with your friends and colleagues.

As you can see from Viper's help message, you can specify a project name at startup::

    nex@nex:~/$ viper-cli -h
    usage: viper-cli [-h] [-p PROJECT]

    optional arguments:
      -h, --help            show this help message and exit
      -p PROJECT, --project PROJECT
                            Specify a new or existing project name


When doing so, Viper will try to open an existing project with the given name and if it doesn't exist it will initialize it under the ``projects/`` folder.

If you opened a project, it will appear both in a startup message as well as in Viper's terminal::

    nex@nex:~/$ viper-cli -p test
             _                   
            (_) 
       _   _ _ ____  _____  ____ 
      | | | | |  _ \| ___ |/ ___)
       \ V /| | |_| | ____| |    
        \_/ |_|  __/|_____)_| v1.3
              |_|
        
    You have 0 files in your test repository
    test shell > 

From within the terminal, you can see which projects exist and eventually you can switch from one to another::

    test1 shell > projects --list
    [*] Projects Available:
    +--------------+--------------------------+---------+
    | Project Name | Creation Time            | Current |
    +--------------+--------------------------+---------+
    | test2        | Fri Jul 11 02:05:55 2014 |         |
    | test1        | Fri Jul 11 02:05:51 2014 | Yes     |
    +--------------+--------------------------+---------+
    test1 shell > projects --switch test2
    [*] Switched to project test2
    test2 shell > 

More details on the ``projects`` command are available in the :doc:`commands` chapter.

Sessions
========

Most of commands and especially modules provided by Viper, are designed to operate on a single file, being a Windows executable or a PDF or whatever else.

In order to do so, you'll have to open the file of your choice and every time you do so a new **session** will be created. You'll be able to see the name of the file you opened in the terminal::

    shell > open 9f2520a3056543d49bb0f822d85ce5dd
    [*] Session opened on ~/viper/binaries/2/d/7/9/2d79fcc6b02a2e183a0cb30e0e25d103f42badda9fbf86bbee06f93aa3855aff
    shell darkcomet.exe >

From then on, every command and module you launch will execute against the file you just opened (if the module requires to do so obviously).

Similarly to the projects, you can just as easily see which sessions you have currently opened::

    shell darkcomet.exe > sessions --list
    [*] Opened Sessions:
    +---+-----------------+----------------------------------+---------------------+---------+
    | # | Name            | MD5                              | Created At          | Current |
    +---+-----------------+----------------------------------+---------------------+---------+
    | 1 | blackshades.exe | 0d1bd081974a4dcdeee55f025423a72b | 2014-07-11 02:28:45 |         |
    | 2 | poisonivy.exe   | 22f77c113cc6d43d8c12ed3c9fb39825 | 2014-07-11 02:28:49 |         |
    | 3 | darkcomet.exe   | 9f2520a3056543d49bb0f822d85ce5dd | 2014-07-11 02:29:29 | Yes     |
    +---+-----------------+----------------------------------+---------------------+---------+

You can eventually decide to switch to a different one::

    shell darkcomet.exe > sessions --switch 1
    [*] Switched to session #1 on ~/viper/binaries/1/5/c/3/15c34d2b0e834727949dbacea897db33c785a32ac606c0935e3758c8dc975535
    shell blackshades.exe > 

You can also abandon the current session with the ``close`` command (the session will remain available if you wish to re-open it later)::

    shell blackshades.exe > close
    shell > 

A session will also keep track of the results of the last ``find`` command so that you'll be able to easily open new sessions without having to perform repeated searches on your repository. You can find more details about this in the :doc:`commands` chapter.

Please note that if you switch to a whole different project, you'll lose the opened sessions.

Commands & Modules
==================

The operations you can execute within Viper are fundamentally distinguished between **commands** and **modules**. Commands are functions that are provided by Viper's core and enable you to interact with the file repository (by adding, searching, tagging and removing files), with projects and with sessions. They are static and they should not be modified.

Modules are plugins that are dynamically loaded by Viper at startup and are contained under the ``modules/`` folder. Modules implement additional analytical functions that can be executed on an opened file or on the whole repository, for example: analyzing PE32 executables, parsing PDF documents, analyzing Office documents, clustering files by fuzzy hashing or imphash, etc.

Modules are the most actively developed portion of Viper and they represent the most important avenue for contributions from the community: if you have an idea or you want to re-implement a script that you have lying around, make sure you `submit it`_ to Viper.

.. _submit it: https://github.com/viper-framework/viper

Database
========

The database that stores all meta inforation is per default in an sqlite database stored at::
   
    $HOME/.viper/viper.db

Binaries
========

The files are stored in a folder structure within::

    $HOME/.viper/binaries
