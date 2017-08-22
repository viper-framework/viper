Create new modules
==================

Viper in itself is simply a framework, modules are what give it analytical capabilities. We receive and include new modules all the time from contributors, but there are always new features to add. If you have an idea, you should implement a module for it and contribute it back to the community.

The following paragraphs introduce you to the first steps to create a new module.


First steps
-----------

First thing first, you need to create your *.py* script under the ``modules/`` directory: all modules are dynamically loaded by Viper from that folder exclusively. You can create subfolders and place your modules anywhere, Viper will be able to find them.

Any module needs to have some basic attributes that will make it recognizable. It needs to be a Python class inheriting ``Module``, it needs to have a ``cmd`` and ``description`` attribute and it needs to have a ``run()`` function. For example the following would be a valid, although not very useful, Viper module:

    .. code-block:: python
        :linenos:

        from viper.common.abstracts import Module

        class MyModule(Module):
            cmd = 'mycmd'
            description = 'This module does this and that'

            def run(self):
                print("Do something.")


Arguments
---------

When a module is invoked from the Viper shell it can be provided with a number of arguments and options. These should be parsed with the python ``argparse`` module as show in the example below.


    .. code-block:: python
        :linenos:

        from viper.common.abstracts import Module

        class MyModule(ModuleName):
            cmd = 'mycmd'
            description = 'This module does this and that'
            authors = ['YourName']

            def __init__(self):
                super(ModuleName, self).__init__()
                self.parser.add_argument('-t', '--this', action='store_true', help='Do This Thing')
                self.parser.add_argument('-b', '--that', action='store_true', help='Do That')

            def run(self):
                if self.args.this:
                    print("This is FOO")
                elif self.args.that:
                    print("That is FOO")

Using the Config File
---------------------

Viper provides a config file that will allow you to store user editable sections in a single file rather than inside the modules.

    /usr/share/viper/viper.conf.sample

You can easily access the config file:

    .. code-block:: python
        :linenos:

        from viper.core.config import __config__

        cfg = __config__


From here you can access any element in the config file by name:

    .. code-block:: python
        :linenos:

        from viper.core.config import Config

        cfg = Config()

        config_item = cfg.modulename.config_item

        # Example Getting VirusTotal Key

        vt_key = cfg.virustotal.virustotal_key



Using common config settings for outbound http connections
----------------------------------------------------------

A common use case for modules is to implement the API of an external web service (e.g. https://koodous.com/).
The (great!) requests library (https://github.com/requests/requests/) provides an easy interface for making
outbound http connections.
Viper provides a global configuration section ``[http_client]`` where certain requests options can be set
for Proxies, TLS Verfication, CA_BUNDLE and TLS Client Certificates.
Please check the current ``viper.conf.sample``  for more details.

When implementing a custom module settings from the global ``[http_client]]`` can be overridden by specifying
them again in the configuration section of the custom module and then calling the ``Config.parse_http_client``
method for the custom module configuration section. Example:

    .. code-block:: ini
        :linenos:

        # viper.conf

        [http_client]
        https_proxy = http://prx1.example.internal:3128
        tls_verify = True

        [mymodule]
        base_url = https://myapi.example.internal
        https_proxy = False
        tls_verify = False


    .. code-block:: python
        :linenos:

        import requests
        from viper.common.abstracts import Module
        from viper.core.config import __config__

        cfg = __config__
        cfg.parse_http_client(cfg.mymodule)

        class MyModule(Module):
            cmd = 'mycmd'
            description = 'This module does this and that'

            def run(self):
                url = cfg.mymodule.base_url
                r = requests.get(url=url, headers=headers, proxies=cfg.mymodule.proxies, verify=cfg.mymodule.verify, cert=cfg.mymodule.cert)


Accessing the session
---------------------

In most cases, you will probably want to execute some analysis function on the currently opened file and in order to do so you'll need to access the session. Sessions are internally made available through a global object called ``__sessions__``, which has the following attributes:

    * ``__sessions__.current``: a ``Session`` object for the currently opened file.
    * ``__sessions__.sessions``: the list of all ``Session`` objects opened during the current Viper execution.
    * ``__sessions__.find``: a list contains all the results from the last executed ``find`` command.

A ``Session`` object has the following attributes:

    * ``Session.id``: an incremental ID for the session.
    * ``Session.created_at``: the date and time when the session was opened.
    * ``Session.file``: a ``File`` object containing common attributes of the currently opened file (generally speaking, the same information returned by the ``info`` command).

Following are the information available on the opened file:

    * ``__sessions__.current.file.path``
    * ``__sessions__.current.file.name``
    * ``__sessions__.current.file.size``
    * ``__sessions__.current.file.type``
    * ``__sessions__.current.file.mime``
    * ``__sessions__.current.file.md5``
    * ``__sessions__.current.file.sha1``
    * ``__sessions__.current.file.sha256``
    * ``__sessions__.current.file.sha512``
    * ``__sessions__.current.file.crc32``
    * ``__sessions__.current.file.ssdeep``
    * ``__sessions__.current.file.tags``

Here is an example:

    .. code-block:: python
        :linenos:

        from viper.common.abstracts import Module
        from viper.core.session import __sessions__

        class MyModule(Module):
            cmd = 'mycmd'
            description = 'This module does this and that'

            def run(self):
                # Check if there is an open session.
                if not __sessions__.is_set():
                    # No open session.
                    return

                # Print attributes of the opened file.
                print("MD5: " + __sessions__.current.file.md5)

                # Do something to the file.
                do_something(__sessions__.current.file.path)


Accessing the database
----------------------

In case you're interested in automatically retreiving all files stored in the local repository or just a subset, you'll need to access the local database. Viper provides an interface called ``Database()`` to be imported from ``viper.core.database``.

You can then use the ``find()`` function, specify a key and an optional value and you will obtain a list of objects you can loop through. For example:

    .. code-block:: python
        :linenos:

        from viper.common.abstracts import Module
        from viper.core.database import Database

        class MyModule(Module):
            cmd = 'mycmd'
            description = 'This module does this and that'

            def run(self):
                db = Database()
                # Obtain the list of all stored samples.
                samples = db.find(key='all')

                # Obtain the list of all samples matching a tag.
                samples = db.find(key='tag', value='apt')

                # Obtain the list of all samples with notes matching a pattern.
                samples = db.find(key='note', value='maliciousdomain.tld')

                # Loop through results.
                for sample in samples:
                    print("Sample " + sample.md5)


Printing results
----------------

Viper provides several function to facilitate and standardize the output of your modules. Viper uses a logging function to return the output to the console or web application.
The format is ``self.log('type', "Your Text")`` and the following types are made available in Viper.

    * ``info``: prints the message with a ``[*]`` prefix.
    * ``warning``: prints the message with a yellow ``[!]`` prefix.
    * ``error``: prints the message with a red ``[!]`` prefix.
    * ``success``: prints the message with a green ``[+]`` prefix.
    * ``item``: prints an item from a list.
    * ``table``: prints a table with headers and rows.

You can also easily print tables, such as in the following example:

    .. code-block:: python
        :linenos:

        from viper.common.abstracts import Module

        class MyModule(Module):
            cmd = 'mycmd'
            description = 'This module does this and that'

            def run(self):
                self.log('info', "This is Something")
                self.log('warning', "This is the warning Text")

                # This is the header of the table.
                header = ['Column 1', 'Column 2']
                # These are the rows.
                rows = [
                    ['Row 1', 'Row 1'],
                    ['Row 2', 'Row 2']
                ]

                self.log('table', dict(header=header, rows=rows))

