find
====

The find command is the primary method for searching data stored in the database

::

    shell > find -h
    usage: find [-h] [-t] <all|latest|name|md5|sha256|tag> <value>

    Options:
        --help (-h)	Show this help message
        --tags (-t)	List tags

    shell > find tag darkcomet
    +----+------------------------------------------------------------------+-----------------------+----------------------------------+
    | #  | Name                                                             | Mime                  | MD5                              |
    +----+------------------------------------------------------------------+-----------------------+----------------------------------+
    | 1  | VirusShare_3d0c25c95714deed4a7313e0dfc903ca                      | application/x-dosexec | 3d0c25c95714deed4a7313e0dfc903ca |
    | 2  | VirusShare_4c450a434992367d668a4ebaf42c224c                      | application/x-dosexec | 4c450a434992367d668a4ebaf42c224c |
    | 3  | VirusShare_500064addacc7c0956c7d7ff86538027                      | application/x-dosexec | 500064addacc7c0956c7d7ff86538027 |
    | 4  | VirusShare_f8072c5003308e219213671ccc27757a                      | application/x-dosexec | f8072c5003308e219213671ccc27757a |
    | 5  | VirusShare_1d783f4e01ca3010e8159f9d7f794adb                      | application/x-dosexec | 1d783f4e01ca3010e8159f9d7f794adb |
    | 6  | VirusShare_bef0efd2fecf19f0f5a57c63955c342c                      | application/x-dosexec | bef0efd2fecf19f0f5a57c63955c342c |

