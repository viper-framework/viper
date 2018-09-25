===============
HTTP Interfaces
===============

Viper has two HTTP interfaces that can optionally be enabled alongside the console access.

* Web interface
* REST based API interface

The first one provides a graphical alternative to the traditional command-line interface,
while the second one can be used to easily integrate Viper with other tools.


Security Considerations
=======================

Both the web interface and the REST API are implemented using the open source Python web framework
Django (https://www.djangoproject.com/). Django is very widely used and the developers put a strong
emphasis on web security.

Viper uses built-in features of Django to provide username/password based login to the web interface
and token based authentication for the REST API. Django also provides a built-in web server that can 
be used to run a HTTP or a HTTPS web server. This works fine for small setups (e.g. single user with
only a limited number of samples), but it is not recommended for bigger production scenarios.

Although both interfaces are developed with security in mind, users MUST be aware that exposing them
to the Internet could potentially have a severe impact on the security of your system(s).

Malicious users/attackers that are able to gain access to the web interface or the REST API will not
only have **full access to your Viper sample database** but will also be able to **execute commands 
on the hosting system**. Access could be gained by stealing/phishing the username/password,
brute-forcing credentials or through authentication bypasses caused by implementation mistakes in
Viper or bugs/design flaws in Django.


Web Interface
=============

Viper comes with a basic HTML5 browser interface that can run alongside the command-line interface.

Its main features are:

    * Project Switching / Creation
    * Multiple File Upload
    * File Download
    * Extraction of Compressed uploads
    * Full Search (including tag, name, mime, note, type)
    * Hex Viewer
    * Run Modules
    * Enter Notes
    * Add / Delete / Modify Yara rules
    * Add / Delete / Modify Tags

Configuration
-------------

For the configuration of the web interface please refer to the ``[web]`` section in your ``viper.conf``
file. There you can specify the IP address (e.g. 0.0.0.0 or 127.0.0.1) and port to listen on.
Additionally you can configure HTTPS using TLS. This requires an x509 certificate and private key.
Lastly you can setup the initial admin account and its password::

    [web]
    host = 0.0.0.0
    port = 8080
    tls = False
    certificate =
    key =
    admin_username = admin
    admin_password = changeme

Launching the web interface
------------------------

To launch the web application, change into the viper directory and run the ``viper-web`` script.
By default it launches a single threaded http Django development web server on ``localhost:8080``
.
Please note that if there is no ``admin_password`` set, then a random password will be generated::

    user@localhost:~/viper_django/$ ./viper-web
    [!] Yara rule directory not found - copying default rules (/home/user/viper_django/viper/data/yara) to: /home/user/.viper/yara
    [!] There are outstanding Django DB migrations
    [+] Applied outstanding migrations
    [+] Created "admin" with initial password: T8UcpRTPxW
    [*] Starting Web Server on 127.0.0.1:8080
    Performing system checks...

    System check identified no issues (0 silenced).
    February 04, 2018 - 14:27:59
    Django version 2.0.2, using settings 'viper.web.settings'
    Starting development server at http://127.0.0.1:8080/
    Quit the server with CONTROL-C.

You can set the listening IP address and port on the commandline with parameters ``-H`` and ``-p``::

    user@localhost:~/viper_django$ ./viper-web -h
    usage: viper-web [-h] [-H HOST] [-p PORT] [--tls] [-c CERTIFICATE] [-k KEY]

    optional arguments:
      -h, --help            show this help message and exit
      -H HOST, --host HOST  bind to host (e.g. 127.0.0.1 or 0.0.0.0)
      -p PORT, --port PORT  bind to port (e.g. 8080)
      --tls                 enable TLS
      -c CERTIFICATE, --certificate CERTIFICATE
                            path to .crt file
      -k KEY, --key KEY     path to .key file

You can also start an HTTPS web server with TLS enabled. This requires a regular x509 SSL/TLS certificate and key::

    $: ./viper-web -H 0.0.0.0 -p 443 --tls --certificate viper.pem --key viper.key
    [*] Using PEID info from directory: /home/user/.viper/peid
    [*] Using Yara rules from directory: /home/user/.viper/yara
    [!] There are outstanding Django DB migrations
    [+] Applied outstanding migrations
    [+] Created "admin" with initial password: nKAmWJluCS
    [*] Starting Web Server on 0.0.0.0:8443
    Validating models...

    System check identified no issues (0 silenced).
    February 04, 2018 - 17:49:48
    Django version 2.0.1, using settings 'viper.web.settings'
    Starting development server at https://0.0.0.0:443/
    Using SSL certificate: ssl-cert.pem
    Using SSL key: ssl-cert.key
    Quit the server with CONTROL-C.

API
===

Viper provides a REST API through which the samples in all projects can be accessed and almost all
commands that are available in the CLI can be executed. The REST API is a crucial part of the
web interface and is therefore automatically started by the ``viper-web`` script.

In the past, the REST API was started separately from the web interface. This is no longer possible
and the ``viper-api`` script has been removed.

The REST API is implemented using the [Django REST framework](http://www.django-rest-framework.org/),
short DRF and is reachable after starting ``viper-web`` at:

   http://127.0.0.1:8080/api/v3/

Additionally Viper makes use of [django-rest-swagger](https://marcgibbons.com/django-rest-swagger/),
which automatically creates an interactive API documentation; all technical details about API
endpoints and how to use them can be found at:

   http://127.0.0.1:8080/api/v3/docs/

All requests to the REST API need to be authenticated with the only exception being a test interface
(http://127.0.0.1:8080/api/v3/test/). Authentication can either be done by providing a username/password
or by sending an authorization header containing a token. These credentials can be managed
in the Django admin interface (http://127.0.0.1:8080/admin/).

Using tokens is the recommended way of accessing the REST API.

Example: Uploading a file as a new sample using curl looks like this (note the trailing slash)::

    curl -X POST -H 'Authorization: Token 4851aa7772e5a2638d7e3dbe9405d3d4a822815a' -S -F "file=@/tmp/file1.txt;type=text/plain;filename=your_file_name.txt" http://127.0.0.1:8080/api/v3/project/default/malware/upload/

Response (HTTP Status Code: 201 Created)::

    [{
        "url": "http://127.0.0.1:8080/api/v3/project/default/malware/24a05ea7cca0b976dd3dea2b436627bd70a303e91a82daa58d104f98eb5b7937/",
        "links": [
                "http://127.0.0.1:8080/api/v3/project/default/malware/24a05ea7cca0b976dd3dea2b436627bd70a303e91a82daa58d104f98eb5b7937/analysis/",
                "http://127.0.0.1:8080/api/v3/project/default/malware/24a05ea7cca0b976dd3dea2b436627bd70a303e91a82daa58d104f98eb5b7937/note/",
                "http://127.0.0.1:8080/api/v3/project/default/malware/24a05ea7cca0b976dd3dea2b436627bd70a303e91a82daa58d104f98eb5b7937/tag/"
        ],
        "data": {
            "created_at":"2018-02-04 17:56:53.172641","sha256":"24a05ea7cca0b976dd3dea2b436627bd70a303e91a82daa58d104f98eb5b7937",
            "parent":null,
            "size":192,
            "sha1":"434656fde3f62bef3ed2d1fe2ac88085fbc17150",
            "ssdeep":"3:SQg3D7DQFCDgJMNLm9cFXmdd3WG/zAhlAHnd1FIati+v3sQ9scKJLAH4:SQg3D7DQFC8qK+wdd3WGYqvFIaFv3sQY",
            "crc32":"95AF7564",
            "type":"ASCII text",
            "id":1,
            "mime":"text/plain",
            "sha512":"166a850aa4423b887f14d74eba7a98c8df76bf4584385ce14d7719d5524784f878afae080a1ee2c26a92f98100735a10d06b78ffec9091fb10b21bc9d294c508",
            "parent_id":null,
            "md5":"8c15c2e4a48fe98483c7833bf0044fc4",
            "name":"your_file_name.txt"
       }
    }]

User management
---------------

The credentials can be managed in the Django admin interface (http://127.0.0.1:8080/admin/).

Using Viper in a (web) production environment
-------------------------------------------

In production use, its often not recommended to use the Django development web server. There are
many generic descriptions of how to run a Django application in e.g. Apache, Nginx or uWSGI.

For Viper there is currently no finished step-by-step guide. Please feel free to send us a Pull
Request on Github..  :-D  https://github.com/viper-framework/viper/pulls


FAQ
===

Q: What is the default username and password for the web interface?
A: The default username is "admin" and the password will be auto generated (or the value of ``admin_password`` in your ``viper.conf`` will be used)

Q: I didn't change (or write down) the auto generated password? How can I log in?
A: The easiest way is to delete the Django database (``$storage_path/admin.db``) and restart ``viper-web``.

Q: Where can I find the API tokens?
A: You can view and edit tokens in the Django admin site: http://127.0.0.1:8080/admin/authtoken/token/
