EXIF Module
============


The email modules provides a method to extract Exif information from files.

::

    shell sample.exe > exif

    [*] MetaData:
    +---------------------------+--------------------------------------------------------+
    | Key                       | Value                                                  |
    +---------------------------+--------------------------------------------------------+
    | EXE:AssemblyVersion       | 0.0.0.0                                                |
    | EXE:CharacterSet          | 04B0                                                   |
    
    ...
    
    | EXE:InitializedDataSize   | 8192                                                   |
    | EXE:InternalName          | IntelRapidStart.exe                                    |
    | EXE:LanguageCode          | 0000                                                   |
    | EXE:LegalCopyright        |                                                        |
    | EXE:LinkerVersion         | 8.0                                                    |
    | EXE:MachineType           | 332                                                    |
    | EXE:OSVersion             | 4.0                                                    |
    | EXE:ObjectFileType        | 1                                                      |
    | EXE:OriginalFilename      | IntelRapidStart.exe                                    |
    | EXE:PEType                | 267                                                    |
    | EXE:ProductVersion        | 0.0.0.0                                                |
    | EXE:ProductVersionNumber  | 0.0.0.0                                                |
    | EXE:Subsystem             | 2                                                      |
    | EXE:SubsystemVersion      | 4.0                                                    |
    | EXE:TimeStamp             | 2014:03:08 23:09:52+00:00                              |
    | EXE:UninitializedDataSize | 0                                                      |
    | ExifTool:ExifToolVersion  | 9.46                                                   |
    | File:Directory            | ../../samples                                          |
    | File:FileAccessDate       | 2014:05:16 14:23:17+01:00                              |
    | File:FileInodeChangeDate  | 2014:05:16 14:22:56+01:00                              |
    | File:FileModifyDate       | 2014:05:16 14:22:56+01:00                              |

    ...
    
The exif module will run against most file types and is capable of much more. Exmples include extracting GPS data from images, Idnetigy author information in Office documents.

