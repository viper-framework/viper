.. Modules chapter frontpage


=======
Modules
=======

Modules constitute the most important part of the tool. Ideally Viper should grow as a collection of as many modules as possible implementing analysis capabilities for different file formats like PDF or Office documents and providing all kinds of lookups. I haven't spent much time as I should have on writing modules, mainly because I focused on implementing a solid skeleton for the framework, but at this moment it includes:

yara: scan the opened file or the full repository with the provided Yara signatures.
virustotal: looks up the opened file on VirusTotal.
cuckoo: submits the opened file to a Cuckoo API server.
image: submits an opened JPEG to Ghiro.
pe: parses PE headers, extract imports and exports, extract resources and scan the repository for common ones, calculate and scan for imphash, compiletime and PEiD.
fuzzy: scans the repository for matching ssdeep hashes.
strings: extract strings from the opened file.

Creating a module is easy. Just create a new file in the modules/ directory and start with a skeleton similar to the one found in templates:


.. toctree::
   template
   email
   cuckoo
   debup
