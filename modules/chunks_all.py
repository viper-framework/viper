from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.storage import get_sample_path

try:
    import pydeep
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

class Chunks_All(Module):
    cmd = 'chunks_all'
    description = 'Splits all samples into chunks of 250 characters and hashes each chunk'
    
    def __init__(self):
        super(Chunks_All, self).__init__()
        self.parser.add_argument('-r', '--raw', action='store_true', help='Create hashed chunks for all raw samples')
        self.parser.add_argument('-d', '--decoded', action='store_true', help='Create hashed chunks for all decoded samples')
        
    def usage(self):
            print('usage: chunks_all [-h][-r][-d]')

    def run(self):
        super(Chunks_All, self).run()
        if self.args is None:
            return
        
        # Check dependencies
        if not HAVE_PYDEEP:
           print_error('Missing dependency, install pydeep (`pip install pydeep`)')
           return  


        # Retrieve all the samples from the database
        db = Database()
        samples = db.find(key='all')  
        
        if self.args.raw:   
            
            # Create chunked hashes for all samples
            count = 0
            success = 0
            for sample in samples:
                print(count)
                count += 1
                path = get_sample_path(sample.sha256)
                print(path)
                new_path = path + '(raw)(chunks)'         
                   
                # Read in the file
                f = open(path)
                contents = f.read()
                f.close()
                
                # Create the output file
                f = open(new_path, 'w') 
                
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
                f.close()
                success += 1
                print_success('Complete')
                
            print_info(str(success) + ' samples were successfully processed')
        
        elif self.args.decoded:    
            
            # Create a list of sample names
            sample_names = []
            for sample in samples:
                sample_names.append(str(sample.sha256)) 
                
            # Check if all samples have been decoded
            all_decoded = True
            for sample in sample_names:
                path = get_sample_path(sample) + '(decoded)'
                try:
                    f = open(path)
                    f.close()
                except IOError:
                     all_decoded = False
                     print_error('Not all samples have been decoded. Run the decode_all command and then try again')
                     break
                 
            if all_decoded:  
                
                # Create chunked hashes for all samples
                count = 0
                success = 0
                for sample in samples:
                    print(count)
                    count += 1
                    path = get_sample_path(sample.sha256)
                    print(path)
                    new_path = path + '(decoded)(chunks)'         
                       
                    # Read in the file
                    f = open(path)
                    contents = f.read()
                    f.close()
                    
                    # Create the output file
                    f = open(new_path, 'w') 
                    
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
                    f.close()   
                    success += 1
                    print_success('Complete')
                    
                print_info(str(success) + ' samples were successfully processed')
                
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
                
        

        
        