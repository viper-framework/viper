from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    import pydeep
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

class Chunks(Module):
    cmd = 'chunks'
    description = 'Normalises a sample, splits it into chunks of 250 characters, and hashes each chunk'

    def run(self):
        
        # Check for an open session
        if not __sessions__.is_set():
            print_error('No session opened')
            return
        
        # Check dependencies
        if not HAVE_PYDEEP:
           print_error('Missing dependency, install pydeep (`pip install pydeep`)')
           return
    
        # Get the file path
        path = __sessions__.current.file.path
        
        # Read in the file
        f = open(path)
        contents = f.read()
        f.close()
        
        # Create the output file
        f = open(path + '(raw)(chunks)', 'w') 
        
        # Remove whitespace
        contents = contents.replace(' ', '')
        contents = contents.replace('\t', '')
        contents = contents.replace('\n', '')

        # Split into chunks
        chunks = [contents[i:i+250] for i in range(0, len(contents), 250)]      
        
        # Hash every chunk and write it to file
        for chunk in chunks:
            hashed_chunk = pydeep.hash_buf(chunk)
            f.write(hashed_chunk + '\n')
            print(hashed_chunk)
        f.close()
        print_success('Complete')
        
        