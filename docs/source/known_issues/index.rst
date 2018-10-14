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


Error Messages in log: ssl.SSLEOFError: EOF occurred in violation of protocol
=============================================================================

When running the built-in HTTPS server several error messages are logged, then the favicon is accessed.
This does not represent a problem and the favicon is loaded and display. So this is currently in status ``wontfix``.

Log::

    2018-02-05 14:29:33 - django.server - INFO - basehttp.py:124 - "GET /favicon.ico HTTP/1.1" 301 0
    Traceback (most recent call last):
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 138, in run
        self.finish_response()
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 180, in finish_response
        self.write(data)
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 279, in write
        self._write(data)
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 453, in _write
        self.stdout.write(data)
      File "/usr/lib/python3.4/socket.py", line 394, in write
        return self._sock.send(b)
      File "/usr/lib/python3.4/ssl.py", line 702, in send
        v = self._sslobj.write(data)
    ssl.SSLEOFError: EOF occurred in violation of protocol (_ssl.c:1638)
    2018-02-05 14:29:33 - django.server - ERROR - basehttp.py:124 - "GET /favicon.ico HTTP/1.1" 500 59
    ----------------------------------------
    Exception happened during processing of request from ('192.168.92.66', 52014)
    Traceback (most recent call last):
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 138, in run
        self.finish_response()
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 180, in finish_response
        self.write(data)
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 279, in write
        self._write(data)
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 453, in _write
        self.stdout.write(data)
      File "/usr/lib/python3.4/socket.py", line 394, in write
        return self._sock.send(b)
      File "/usr/lib/python3.4/ssl.py", line 702, in send
        v = self._sslobj.write(data)
    ssl.SSLEOFError: EOF occurred in violation of protocol (_ssl.c:1638)

    During handling of the above exception, another exception occurred:

    Traceback (most recent call last):
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 141, in run
        self.handle_error()
      File "/home/robbie/work/viper/venv/lib/python3.4/site-packages/django/core/servers/basehttp.py", line 86, in handle_error
        super().handle_error()
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 368, in handle_error
        self.finish_response()
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 180, in finish_response
        self.write(data)
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 274, in write
        self.send_headers()
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 331, in send_headers
        if not self.origin_server or self.client_is_modern():
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 344, in client_is_modern
        return self.environ['SERVER_PROTOCOL'].upper() != 'HTTP/0.9'
    TypeError: 'NoneType' object is not subscriptable

    During handling of the above exception, another exception occurred:

    Traceback (most recent call last):
      File "/usr/lib/python3.4/socketserver.py", line 305, in _handle_request_noblock
        self.process_request(request, client_address)
      File "/usr/lib/python3.4/socketserver.py", line 331, in process_request
        self.finish_request(request, client_address)
      File "/usr/lib/python3.4/socketserver.py", line 344, in finish_request
        self.RequestHandlerClass(request, client_address, self)
      File "/usr/lib/python3.4/socketserver.py", line 673, in __init__
        self.handle()
      File "/home/robbie/work/viper/venv/lib/python3.4/site-packages/django/core/servers/basehttp.py", line 154, in handle
        handler.run(self.server.get_app())
      File "/usr/lib/python3.4/wsgiref/handlers.py", line 144, in run
        self.close()
      File "/usr/lib/python3.4/wsgiref/simple_server.py", line 35, in close
        self.status.split(' ',1)[0], self.bytes_sent
    AttributeError: 'NoneType' object has no attribute 'split'
    ----------------------------------------
    2018-02-05 14:29:33 - django.server - INFO - basehttp.py:124 - "GET /static/viperweb/images/favicon.png HTTP/1.1" 200 2041

