.. Installation chapter frontpage

Installation
============

Viper is written in Python so should be compatible across most platforms that can meet the requirements. 

Viper has been tested on the following platforms

* Ubuntu 12.10 x64
* Ubuntu 14.04 x64

To begin checkout the latest version of viper from GitHub

``$ git clone https://github.com/botherder/viper.git``

Pre-Reqs
---------
There are a few requirements that need installing before starting with viper. 

* gcc
* python-dev
* python-socksipy
* pyhton-pip

These can be installed with the following command

``# apt-get install gcc pyhton-dev python-socksipy python-pip``

At this point, I recommend installing `ssdeep <http://ssdeep.sourceforge.net/>`_ and `Yara <http://plusvic.github.io/yara/>`_ following the respective instructions. 

Once completed you can install the remaining Python dependencies with pip.

``# cd viper/``
``# pip install -r requirements.txt``

First Launch
------------

Once you are finished run the viper application and ensure it starts with no errors you should see the following

``$ ./viper.py``

::

    thehermit@TechAnarchy:~/GitHub/viper$ ./viper.py
             _                   
            (_) 
       _   _ _ ____  _____  ____ 
      | | | | |  _ \| ___ |/ ___)
       \ V /| | |_| | ____| |    
        \_/ |_|  __/|_____)_| v0.1-dev
              |_|
        
    You have 122 files in your repository
    shell >    





