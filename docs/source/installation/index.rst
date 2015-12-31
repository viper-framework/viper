Installation
============

Viper is written in Python and **it requires Python 2.7** to function properly. In this documentation we will use Debian GNU/Linux based distributions, such as Ubuntu, as a reference platform. The following installation instructions should apply similarly to other distributions and possibly to Mac OS X as well, although it has not been properly tested.

Before proceeding, you should make sure you have the basic tools installed to be able to compile additional Python extensions::

    $ sudo apt-get install gcc python-dev python-pip

In order to have support for certain modules, you will need to install the following dependencies too before proceeding::

    $ sudo apt-get install libssl-dev swig libffi-dev

Core dependencies
-----------------

Viper makes use of a number of Python library for its core functioning, which can be installed with the command::

    $ sudo pip install SQLAlchemy PrettyTable python-magic

In addition you should install ssdeep with pydeep. After you downloaded the source code for ssdeep from the `official website`_, proceed with the following::

    $ tar -zxvf ssdeep-X.XX.tar.gz
    $ cd ssdeep-X.XX
    $ ./configure && make
    $ sudo make install
    $ sudo pip install pydeep

Viper can retrieve files remotely through `Tor`_, if you're interested in such feature you should install SocksiPy::

    $ sudo apt-get install python-socksipy

You will also clearly need a running Tor daemon, refer to the official website for setup instructions.

Extra dependencies
------------------

Please be aware that all the modules that are available in Viper might have their own dependencies that are unrelated to Viper's core. We will try to make such dependencies available in our ``requirements.txt`` file that you can provide to ``pip``::

    $ sudo pip install -r requirements.txt

In case a dependency is missing or it is not available on PyPi, you should be instructed by the module itself on how to retrieve and install it.

First launch
------------

If everything worked out fine, you should be able to launch Viper's shell without raising any exceptions, like following::

    nex@nex:~/viper$ ./viper.py 
             _                   
            (_) 
       _   _ _ ____  _____  ____ 
      | | | | |  _ \| ___ |/ ___)
       \ V /| | |_| | ____| |    
        \_/ |_|  __/|_____)_| v1.2
              |_|
        
    You have 0 files in your default repository
    shell > 

.. _official website: http://ssdeep.sourceforge.net
.. _Tor: https://www.torproject.org
