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

When a module is invoked from the Viper shell it can be provided with a number of arguments. These are made accessible to the module through the ``self.args`` attribute, which is simply a Python list.

You will need to take care of parsing and interpreting the arguments, for example using Python's ``getopt`` module:


    .. code-block:: python
        :linenos:

        import getopt

        from viper.common.abstracts import Module

        class MyModule(Module):
            cmd = 'mycmd'
            description = 'This module does this and that'

            def run(self):
                try:
                    opts, argv = getopt.getopt(self.args[0:], 'hs', ['help', 'something'])
                except getopt.GetoptError as e:
                    print(e)
                    return

                for opt, value in opts:
                    if opt in ('-h', '--help'):
                        help()
                    elif opt in ('-s', '--something'):
                        print("Do something.")


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
                    # No session opened.
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

Viper provides few functions to facilitate and standardize the output of your modules. Following are the functions available from ``viper.common.out``:

    * ``print_info()``: prints the message with a ``[*]`` prefix.
    * ``print_warning()``: prints the message with a yellow ``[!]`` prefix.
    * ``print_error()``: prints the message with a red ``[!]`` prefix.
    * ``print_success()``: prints the message with a green ``[+]`` prefix.
    * ``print_item()``: prints an item from a list.

You can also easily print tables, such as in the following example:

    .. code-block:: python
        :linenos:

        from viper.common.abstracts import Module
        from viper.common.out import *

        class MyModule(Module):
            cmd = 'mycmd'
            description = 'This module does this and that'

            def run(self):
                print_info("Do something.")

                # This is the header of the table.
                header = ['Column 1', 'Column 2']
                # These are the rows.
                rows = [
                    ['Row 1', 'Row 1'],
                    ['Row 2', 'Row 2']
                ]

                print(table(header=header, rows=rows))
