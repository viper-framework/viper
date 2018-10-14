Installation
============

Viper is written in Python requires **Python >= 3.4**. As of Viper 2.0, Python 2.x is no longer supported. In this documentation we will use Debian GNU/Linux based distributions, such as Ubuntu, as a reference platform. The following installation instructions should apply similarly to other distributions and possibly to Mac OS X as well, although it has not been properly tested.

Before proceeding, you should make sure you have the basic tools installed to be able to compile additional Python extensions::

    $ sudo apt-get install git gcc python3-dev python3-pip

In order to have support for the most basic modules, you will need to install the following dependencies too before proceeding::

    $ sudo apt-get install libssl-dev swig libffi-dev ssdeep libfuzzy-dev unrar p7zip-full

To install Viper::

    $ git clone https://github.com/viper-framework/viper
    $ cd viper
    $ git submodule init
    $ git submodule update
    $ sudo pip3 install setuptools wheel --upgrade
    $ sudo pip3 install .


First launch
------------

If everything worked out fine, you should be able to launch Viper's shell without raising any exceptions, like following::

    nex@nex:~/$ viper-cli
             _
            (_)
       _   _ _ ____  _____  ____
      | | | | |  _ \| ___ |/ ___)
       \ V /| | |_| | ____| |
        \_/ |_|  __/|_____)_| v2.0
              |_|

    You have 0 files in your default repository
    shell >

.. _official website: http://ssdeep.sourceforge.net
.. _Tor: https://www.torproject.org
.. _YARA: http://virustotal.github.io/yara/
.. _YARA-Python: https://github.com/plusvic/yara-python

Uninstall
---------

To uninstall Viper::

    $ cd viper
    $ pip3 uninstall -y viper
    $ pip3 uninstall -y -r requirements.txt


Module Dependencies
------------------

The following dependencies are requried to use specific modules.

Exif::

    $ sudo apt-get intall exiftool

ClamAV::

    $ sudo apt-get install clamav-daemon

Tor::

    $ sudo apt-get install tor

Scraper::

    $ sudo apt-get install libdpkg-perl
