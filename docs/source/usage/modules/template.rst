Module Template
===============

The core template looks like this

::

    from viper.common.out import *
    from viper.common.abstracts import Module
    from viper.core.session import __session__

    class MyModule(Module):
        cmd = 'mymodule'
        description = 'Does something cool'

        def run(self):
            # Do something
            
viper.common.out provides some simple functions to print output such as print_info(), print_item(), print_warning(), print_error() and table(). 
viper.common.abstracts provides the base class Module which is mostly used to identify your class as a valid module and to provide some default attributes for arguments and other helpers. 
viper.core.session provides access to the __session__ object, which contains all the attributes of the currently opened file, including:

* __session__.file.path
* __session__.file.name
* __session__.file.type
* __session__.file.md5
* __session__.file.sha1
* __session__.file.sha256
* __session__.file.sha512
* __session__.file.crc32
* __session__.file.ssdeep
* __session__.file.tags

To check if there is an existing session, you can do:

::

    if __session__.is_set():
        # Do something.
        
When a module is executed through the Viper shell, any argument can be provided to it and they're all accessible as a list under self.args.

If you want to access all the files available in the repository from your module, you need to import the Database class and execute some queries, for example:

::

    from viper.common.out import *
    from viper.common.abstracts import Module
    from viper.core.session import __session__
    from viper.core.database import Database
    from viper.core.storage import get_sample_path

    class MyModule(Module):
        cmd = 'mymodule'
        description = 'Does something cool'

        def run(self):
            db = Database()
            samples = db.find(key='all')
            for sample in samples:
                sample_path = get_sample_path(entry.sha256)
                do_something(sample_path)


At this point you should be able to start experimenting and implementing the functionality of your module. I'd recommend giving a look to the existing modules to get some ideas on how I implemented them.

Conclusions
If you haven't done it yet, I recommend watching the quick screencast that I put together to showcase the basic usage of the tool and the feeling that I'm hoping to achieve.

Viper is licensed under BSD 3-Clause, which I chose in order to encourage and facilitate contributions from the community. As it is now, I admit it might not be of much use. However, my hope is that others will find some potential in it and that we can initiate a collaborative development effort to extent its functionality, improve the framework and add more and more modules to it. Truthfully I don't think I'll be able to make it a usable product by my own, since I believe its value would just rely in the multiplicity of uses that only a diversified community could provide.

To brainstorm, critic or suggest, you can reach me by mail, at @botherder or on FreeNode IRC in the channel ###viper. If there's any interest, I might be covering additional architectural details in future blog posts.
