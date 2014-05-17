Email Module
============


The email modules provides a method to extract information from SMTP Streams, EML and MSG Files.

You can optionally open a session on any of the attachments

::

    shell sample.msg > email -h
    usage: email [-hefrs]

    Options:
        --help (-h)	Show this help message
        --envelope (-e)	Show the email envelope
        --attach (-f)	Show Attachment information
        --header (-r)	Show email Header information
        --all (-a)	Run all the options
        --session (-s)	Switch session to the specified attachment
