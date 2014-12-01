Installation
============

Viper is written in Python and **it requires Python 2.7** to function properly. In this documentation we will use Debian GNU/Linux based distributions, such as Ubuntu, as a reference platform. The following installation instructions should apply similarly to other distributions and possibly to Mac OS X as well, although it has not been properly tested.

Before proceeding, you should make sure you have the basic tools installed to be able to compile additional Python extensions::

    $ sudo apt-get install gcc python-dev python-pip

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
        \_/ |_|  __/|_____)_| v1.1
              |_|
        
    You have 0 files in your default repository
    shell > 

.. _official website: http://ssdeep.sourceforge.net
.. _Tor: https://www.torproject.org

Viper Web behind a Apache proxy
===============================

To place Web Interface of Viper behind a Apache (for SSL / Authentication) do the following:

Install apache
--------------

	$ sudo apt-get install apache2

configure the packages / ports (in case you want them change)::

    $ vi /etc/apache2/ports.conf
	$ vi /etc/apache2/sites-available/default

Enable several Mods and restart apache::


	$ sudo a2enmod proxy 
	$ sudo a2enmod proxy_http
	$ a2enmod ssl
	$ sudo service apache2 restart

To create a SSL server certificate find several tutorials on the web.:: 
	
	$ ...
	$ sudo service apache2 restart

Update site config
------------------

The following apache site config does several things:
	- proxy your port 80 of apache to 9090 of viper web interface:
	- adding SSl Server key
	- Adding Basic Authentication
	- Adding SSL Client side certificate

Edit the file::
	
	$vi /etc/apache2/sites_available/000-default

Example::

	<VirtualHost *:80>
		ServerAdmin your@mail.com
		Servername your.hostname.com
		SSLEngine on
		SSLCertificateKeyFile /etc/apache2/ssl_cert/server.key
		SSLCertificateFile /etc/apache2/ssl_cert/server.crt
		SSLProtocol All -SSLv2 -SSLv3
		SSLOptions +FakeBasicAuth
		# CA in case you have one
		SSLCertificateChainFile /etc/ssl/certs/subca2.crt
		SSLCACertificateFile    /etc/ssl/certs/rootca2.crt
		SSLVerifyClient optional
		SSLVerifyDepth 2
		#Proxy Settings to forward the port 80 to 9090
		ProxyPreserveHost On
		ProxyPass / http://127.0.0.1:9090/
		ProxyPassReverse / http://127.0.0.1:9090/
		# Logging
		ErrorLog ${APACHE_LOG_DIR}/error.log
		# Possible values include: debug, info, notice, warn, error, crit,
		# alert, emerg.
		LogLevel warn
		CustomLog ${APACHE_LOG_DIR}/access.log combined
		<Location />
		Satisfy any
		AuthType        basic
		AuthName        "MALWARE"
		Require         valid-user
		AuthUserFile    /etc/apache2/conf/protected.passwd
		# insert your SSl needs here
		#SSLRequire  %{SSL_CLIENT_S_DN_CN} =~ m/^.*BLA.*/i
		</Location>
	</VirtualHost>

To add the first user to the Basic Auth:::

	$ htpasswd -c /etc/apache2/conf/protected.passwd USERNAME
	
To add a new user to the Basic Auth use:::

	$ htpasswd -b /etc/apache2/conf/protected.passwd USERNAME2

Missing at the moment:
----------------------

	Checking for CRL
