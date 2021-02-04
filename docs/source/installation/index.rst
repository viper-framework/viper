Installation
============

Viper is written in Python and requires **Python >= 3.6**. As of Viper 2.0, Python 2.x is no longer supported. In this documentation we will use Debian GNU/Linux based distributions, such as Ubuntu, as a reference platform. The following installation instructions should apply similarly to other distributions and possibly to Mac OS X as well, although it has not been properly tested.

Before proceeding, you should make sure you have the basic tools installed to be able to compile additional Python extensions::

    $ sudo apt-get install git gcc python3-dev python3-pip

To install Viper from pip::

    $ pip3 install viper-framework

To update Viper from pip::

    $ pip3 install -U viper-framework

The console script `viper` will then be installed in `$HOME/.local/bin`, make sure to have the folder added to your `$PATH`. If you wish to install Viper globally::

    $ sudo pip3 install viper-framework

To install Viper from sources::

    $ git clone https://github.com/viper-framework/viper
    $ cd viper
    $ pip3 install .


First launch
------------

If everything worked out fine, you should be able to launch Viper's shell without raising any exceptions, like following::

    nex@nex:~/$ viper
             _
            (_)
       _   _ _ ____  _____  ____
      | | | | |  _ \| ___ |/ ___)
       \ V /| | |_| | ____| |
        \_/ |_|  __/|_____)_| v2.0
              |_|

    You have 0 files in your default repository

    You do not have any modules installed!
    If you wish to download community modules from GitHub run:
        update-modules
    viper >

On the first launch you will notice that Viper warns you that you do not have any modules installed. Since Viper 2.0 modules are installed separately.

In order to have support for the most basic modules, you will need to install the following dependencies too before proceeding::

    $ sudo apt-get install libssl-dev swig libffi-dev ssdeep libfuzzy-dev unrar-free p7zip-full

You can now download the modules directly from our community GitHub repository using::

    viper > update-modules

Modules will be installed in `$HOME/.viper/modules`. If you wish to do so, you can manually add modules of your own to that folder.

.. _official website: http://ssdeep.sourceforge.net
.. _Tor: https://www.torproject.org
.. _YARA: http://virustotal.github.io/yara/
.. _YARA-Python: https://github.com/plusvic/yara-python

Uninstall
---------

To uninstall Viper::

    $ pip3 uninstall -y viper-framework


Module Dependencies
------------------

The following dependencies are requried to use specific modules.

Exif::

    $ sudo apt-get install exiftool

ClamAV::

    $ sudo apt-get install clamav-daemon

Tor::

    $ sudo apt-get install tor

Scraper::

    $ sudo apt-get install libdpkg-perl
