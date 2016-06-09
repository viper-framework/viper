============
Known issues
============

Various errors when using unicode characters
============================================

unicode and python is a not easy and using unicode in notes, tags or filenames (or other modules where userinput is allowed) might result in unhandled exceptions.

Error storing file names containing unicode characters in database
==================================================================

If you try to store a file with a filename containing Unicode chars it will not be stored to the database.


Problem importing certain modules
=================================

If you experience an issue like::
 
    [!] Something wrong happened while importing the module modules.office: No module named oletools.olevba

You are likely missing dependencies.

To install required python modules run::

    pip install -r requirements.txt


The API interface isn't fully aware of projects
===============================================

Most of the API commands are not able yet to interact with different projects, so most of the commands will
be executed against the default repository.

update.py from 1.1 to 1.2 IOError 'data/web/'
=============================================

If you are running a Viper version 1.1 und using update.py to update to 1.2 you might run into some error like::

    python update.py 
    [!] WARNING: If you proceed you will lose any changes you might have made to Viper.
    Are you sure you want to proceed? [y/N] y
    Traceback (most recent call last):
    File "update.py", line 79, in <module>
      main()
    File "update.py", line 66, in main
      new_local = open(local_file_path, 'w')
      IOError: [Errno 2] No such file or directory: 'data/web/'
      
That issue is known and already adressed in the new version of update.py (you might wanna pull that file manually

PreprocessError: data/yara/index.yara:0:Invalid file extension '.yara'.Can only include .yar
============================================================================================

If you running yara or RAT module and receiving that issue::

    ...
    PreprocessError: data/yara/index.yara:0:Invalid file extension '.yara'.Can only include .yar
    ...
    
    
It is most likely the versions of yara are not correct, try to run::

    viper@viper:/home/viper# yara -version
    yara 2.1

And check for the yara-python bindings::
 
    viper@viper:/home/viper# pip freeze | grep yara
    yara-python==2.1


If you have installed yara-python using pip it is likely you are running an older version of yara (see yara documentation for compiling howto)


