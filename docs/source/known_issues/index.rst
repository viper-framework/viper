============
Known issues
============

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
