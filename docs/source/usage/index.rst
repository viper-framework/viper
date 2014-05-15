.. Usage chapter frontpage

Usage
=====

It's operated through a basic terminal interface:

::

    shell > help
    Commands:
    +---------+-----------------------------------------------+
    | Command | Description                                   |
    +---------+-----------------------------------------------+
    | info    | Show information on the opened file           |
    | help    | Show this help message                        |
    | clear   | Clear the console                             |
    | close   | Close the current session                     |
    | open    | Open a file                                   |
    | find    | Find a file                                   |
    | store   | Store the opened file to the local repository |
    | delete  | Delete the opened file                        |
    +---------+-----------------------------------------------+

    Modules:
    +------------+------------------------------------------------+
    | Command    | Description                                    |
    +------------+------------------------------------------------+
    | fuzzy      | Search for similar files through fuzzy hashing |
    | yara       | Run Yara scan                                  |
    | strings    | Extract strings from file                      |
    | virustotal | Lookup the file on VirusTotal                  |
    | pe         | Extract information from PE32 headers          |
    +------------+------------------------------------------------+

The shell is used to interact with both a number of built-in commands that
are used to populate and query the local repository of binaries.

.. toctree::

    commands/index
    modules/index

