===============
HTTP Interfaces
===============

Viper has two HTTP Components that can optionally be enabled alongside the console access.

    * REST based API interface
    * Web interface

The first one can be used to easily integrate Viper with other tools, while the second one
provides an user-friendly alternative to the traditional command-line interface.


Security Considerations
=======================

Beware that Viper does not provide any security mechanism to protect neither of the HTTP interfaces.
Enabling either interface access to the Internet would severely expose the security of your system,
as users are able not only to access and operate on your Viper repositories, but also execute commands
on the hosting system.

Make sure you take all necessary precautions to implement authentication and encryption whenever necessary
through the tools provided by your firewall and web server.


API
===

Viper provides a REST-based API interface through which you can operate on the repositories as well
as execute almost all functions that you would normally get through the command-line interface.

To start the API::

    user@system:~/$ viper-api
    Bottle server starting up (using WSGIRefServer())...
    Listening on http://127.0.0.1:8080/
    Hit Ctrl-C to quit.

You can bind it on a different IP and port by providing additional options::

    usage: viper-api [-h] [-H HOST] [-p PORT]

    optional arguments:
      -h, --help            show this help message and exit
      -H HOST, --host HOST  Host to bind the API server on
      -p PORT, --port PORT  Port to bind the API server on

The API commands will provide JSON results. Following ou can find details on the commands
available.


/test
-----

    **GET /test**

        Test the API server.

        **Example request**::

            curl http://127.0.0.1:8080/test

        **Example response**::

            {
                "message": "test"
            }

        **Parameters**:

            * None

        **Status codes**:

            * ``200`` - no errors


/file/add
---------

    **POST /file/add**

        Submit a file to Viper.

        **Example request**::

            curl -F file=@FILE -F tags='foo,bar' -X POST http://127.0.0.1:8080/file/add

        **Example response**::

            {
                "message": "added"
            }

        **Parameters**:

            * ``tags``: comma separated list of tags
            * ``file``: path to the file to submit

        **Status codes**:

            * ``200`` - no errors
            * ``500`` - something failed when adding the file


/file/get
---------

    **GET /file/get/** *(str: MD5 or SHA256 hash)*

        Retrieve a file from Viper.

        **Example request**::

            curl http://127.0.0.1:8080/file/get/9ce49435b67d531bbd966186920c90ecf0752e88b79af246886b077c8ec9b649

        **Parameters**:

            * ``hash``: MD5 or SHA256 hash of the file to retrieve

        **Status codes**:

            * ``200`` - no error
            * ``400`` - you did not provide a valid hash (MD5 or SHA256)
            * ``404`` - file not found


/file/delete
------------

    **GET /file/delete/** *(str: MD5 or SHA256 hash)*

        Delete file from Viper.

        **Example request**:

            curl http://127.0.0.1:8080/file/delete/9ce49435b67d531bbd966186920c90ecf0752e88b79af246886b077c8ec9b649


        **Example response**::

            {
                "message": "deleted"
            }

        **Status codes**:

            * ``200`` - no error
            * ``400`` - invalid hash format
            * ``404`` - file not found
            * ``500`` - unable to delete file


/file/find
----------

    **POST /file/find**

        Find a file in Viper default repository or project

        **Example request**::

            curl -F tag=rat http://127.0.0.1:8080/file/find

        **Example response**::

            {
                "default": [
                    {
                        "sha1": "13da502ab0d75daca5e5075c60e81bfe3b7a637f",
                        "name": "darkcomet.exe",
                        "tags": [
                            "rat",
                            "darkcomet"
                        ],
                        "sha512": "7e81e0c4f49f1884ebebdf6e53531e7836721c2ae41729cf5bc0340f3369e7d37fe4168a7434b2b0420b299f5c1d9a4f482f1bda8e66e40345757d97e5602b2d",
                        "created_at": "2015-03-30 23:13:20.595238",
                        "crc32": "2238B48E",
                        "ssdeep": "12288:D9HFJ9rJxRX1uVVjoaWSoynxdO1FVBaOiRZTERfIhNkNCCLo9Ek5C/hlg:NZ1xuVVjfFoynPaVBUR8f+kN10EB/g",
                        "sha256": "2d79fcc6b02a2e183a0cb30e0e25d103f42badda9fbf86bbee06f93aa3855aff",
                        "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
                        "id": 10,
                        "md5": "9f2520a3056543d49bb0f822d85ce5dd",
                        "size": 774144
                    },
                    {
                        "sha1": "dbcea714f43aa06a7f1c3d11cbfd67e4f8e0c23e",
                        "name": "poisonivy3.exe",
                        "tags": [
                            "rat",
                            "poisonivy"
                        ],
                        "sha512": "4b2d61211b059400d5f8701908c6f4cb25a70a44882c67f887301dfc3e02d29b562032fc11333cca29f8bb9a31f0b4679760b0161a63cfc848da1e718dadcd58",
                        "created_at": "2015-03-30 23:13:20.595238",
                        "crc32": "BCD8287D",
                        "ssdeep": "3072:lR+yF1aa8hCqTevS0IjhAPCoGm3vkazsW2mq:lR+KrWCqavSFhmCoGm3h0mq",
                        "sha256": "15846af22582f06fde215a0e506fdf5f88d3262b3d62d1eabd6bdf00f91e0df7",
                        "type": "PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows",
                        "id": 28,
                        "md5": "23c3b61ecdff3d67479d70b5d4d91dea",
                        "size": 143560
                    },
                    ...
                ]
            }

        **Parameters**:

            * ``md5``: search by MD5
            * ``sha256``: search by SHA256
            * ``ssdeep``: search by ssdeep
            * ``tag``: search by tag
            * ``name``: search by name
            * ``all``: retrieve all files
            * ``latest``: retrieve only the most recently added files (specify 1 as the value)
            * ``project``: a project name to search the file in (default is none, you can also specify "all" to search across all projects)

        **Status codes**:

            * ``200`` - no error
            * ``400`` - invalid search term


/file/tags/add
--------------

    **POST /file/tags/add**

        Add one or more tags to one or more files

        **Example request**::

            curl -F tags=foo,bar -F md5=23c3b61ecdff3d67479d70b5d4d91dea http://127.0.0.1/file/tags/add

        **Example response**::

            {
                "message": "added"
            }

        **Parameters**:

            * ``tags``: comma-separated list of tags
            * ``md5``: select by MD5
            * ``sha256``: select by SHA256
            * ``ssdeep``: select by ssdeep
            * ``tag``: select by tag
            * ``name``: select by name
            * ``all``: retrieve all files
            * ``latest``: retrieve only the most recently added files

        **Status codes**:

            * ``200`` - no error
            * ``404`` - file not found


/tags/list
----------

    **GET /tags/list**

        Retrieve a list of all tags

        **Example request**::

            curl http://127.0.0.1:8080/tags/list

        **Example response**::

            [
                "rat",
                "darkcomet",
                "poisonivy",
                "njrat",
                "embedded_win_api",
                "nettraveler",
                "xtreme"
            ]

        **Status codes**:

            * ``200`` - no error#

/file/notes/add
----------------

    **POST /file/notes/add**

        Add a note to a sample

        **Parameters**:

            * ``sha256``: select by SHA256
            * ``title``: title of the note
            * ``body``: body of the note

        **Example request**::

            curl http://127.0.0.1 -F sha256="2e766eabed666510a385544b79a5d344b48a2de2040c62fee9addb19c554ed4c" -F title="asd"  -F body="bodddy" http://127.0.0.1:8080/file/notes/add

        **Example response**::

            {
                "message": "Note added"
            }

        **Status codes**:

            * ``200`` - no error


/file/notes/view
----------------

    **POST /file/notes/view**

        Retrieve a list of all notes

        **Example request**::

            curl -F sha256="2e766eabed666510a385544b79a5d344b48a2de2040c62fee9addb19c554ed4c" http://127.0.0.1:8080/file/notes/view

        **Example response**::

            {
                "message": {
                    "1": {
                        "body": "bodddy",
                        "title": "asd"
                    }
                }
            }

        **Status codes**:

            * ``200`` - no error

/file/notes/update
------------------

    **POST /file/notes/update**

        Updates a note from a sample

        **Parameters**:

            * ``sha256``: select by SHA256
            * ``title``: title of the note
            * ``body``: body of the note
            * ``id``: id of the note

        **Example request**::

            curl http://127.0.0.1 -F sha256="2e766eabed666510a385544b79a5d344b48a2de2040c62fee9addb19c554ed4c" -F title="asd" -F id="1" -F body="bodddy" http://127.0.0.1:8080/file/notes/update

        **Example response**::

            {
                "message": "Note updated"
            }

        **Status codes**:

            * ``200`` - no error

/file/notes/delete
------------------

    **POST /file/notes/delete**

        Delete a note from a sample

        **Parameters**:

            * ``sha256``: select by SHA256
            * ``id``: id of the note

        **Example request**::

            curl http://127.0.0.1 -F sha256="2e766eabed666510a385544b79a5d344b48a2de2040c62fee9addb19c554ed4c" -F id="1" http://127.0.0.1:8080/file/notes/delete

        **Example response**::

            {
                "message": "Note deleted"
            }

        **Status codes**:

            * ``200`` - no error


/projects/list
--------------

    **GET /projects/list**

        Retrieve a list of all projects

        **Example request**::

            curl http://127.0.0.1:8080/projects/list

        **Example response**::

            [
                "project1",
                "project2",
                "project3"
            ]

        **Status codes**:

            * ``200`` - no error
            * ``404`` - no projects found


/modules/run
------------

    **POST /modules/run**

        Execute a command

        **Example request**::

            curl -F sha256=d5042d68b813d5c45c03fe6883f5b83ff079cb9c394ddcc9c84f58e0369c6cdf -F cmdline="pe compiletime" http://127.0.0.1:8080/modules/run

        **Example response**::

            [{'data': 'Compile Time: \\x1b[1m1992-06-20 00:22:17\\x1b[0m', 'type': 'info'}]

        **Parameters**:

            * ``project``: project name
            * ``sha256``: SHA256 hash of the file to execute the command on
            * ``cmdline``: the full command line as you would normally pass to the CLI

        **Status codes**:

            * ``200`` - no error
            * ``404`` - invalid command line

Web Interface
=============

Viper comes with a basic single threaded HTML Browser interface that can run alongside the command-line interface and API.
Its main features are:

    * Project Switching / Creation
    * Multiple File Upload
    * File Download
    * Unpack Compressed uploads
    * Full Search (including tag, name, mime, note, type)
    * Hex Viewer
    * Run Modules
    * Enter Notes
    * Add / Delete / Modify Yara rules
    * Add / Delete / Modify Tags

Launch the web interface
------------------------

To launch the web application move into the viper directory and run the ``web.py`` script.
By default it launches a single threaded bottle web server on localhost:9090::

    user@localhost:~/$ viper-web
    Bottle v0.12.8 server starting up (using WSGIRefServer())...
    Listening on http://localhost:9090/
    Hit Ctrl-C to quit.

You can set the listening IP address and port with options -H and -p ::

    user@localhost:~/$ viper-web -H 0.0.0.0 -p 8080
    Bottle v0.12.8 server starting up (using WSGIRefServer())...
    Listening on http://0.0.0.0:8080/
    Hit Ctrl-C to quit.


Use viper in a (web) production environment
--------------
In production use, its often not recommended to use the default Bottle WSGIRefServer as it can be quite slow and requires manual start.

A dedicated webserver that serves pages on standard ports and with a standardized configuration is possible with viper, but requires some additional setup
To make this work, we are using uwsgi and nginx as stack.

To use nginx as the webserver serving web.py,::

$ sudo apt-get remove apache2 #avoid conflicts
$ sudo apt-get install nginx-full uwsgi uwsgi-plugin-python

Move (or copy) the source to the web directory and make sure the permissions match ::

$ sudo mv viper-* /srv/www/viper
$ chown -R www-data:www-data /srv/www/viper

Change the VIPER_ROOT variable in web.py to reflect your installation.::

 $ sudo vi /srv/www/viper/web.py

Modify the user section, and uncomment and change the following line to reflect your environment::

   VIPER_ROOT ='/srv/www/viper'

Create a file /etc/uwsgi/apps-available/bottle.ini::

   [uwsgi]
   socket = /run/uwsgi/app/bottle/socket
   chdir = /srv/www/viper/
   master = true
   plugins = python
   file = web.py
   uid = www-data
   gid = www-data

Link the /etc/uwsgi/apps-available/bottle.ini file to apps-enabled::

 $ sudo  ln -s /etc/uwsgi/apps-available/bottle.ini /etc/uwsgi/apps-enabled/bottle.ini

Restart nginx and uwsgi::

 $ sudo service nginx restart
 $ sudo service uwsgi restart

Tail the uwsgi logfile to make sure everything works ok: ::

 $ tail -f /var/log/uwsgi/app/bottle.log

And browse to the default port 80 interface of the webserver. You should be greeted with the viper webpage.

Setting up SSL and web-based authentication is out of scope for this document, but infromation can be found in the nginx manual and in one of the many tutorials on the web.
