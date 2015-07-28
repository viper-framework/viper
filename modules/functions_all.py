import subprocess

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.core.project import __project__
from viper.common.utils import get_viper_path

class Functions_All(Module):
    cmd = 'functions_all'
    description = 'Creates a list of functions for all samples'
    
    def __init__(self):
        super(Functions_All, self).__init__()
        self.parser.add_argument('-r', '--raw', action='store_true', help='Create a list of functions for all raw samples')
        self.parser.add_argument('-d', '--decoded', action='store_true', help='Create a list of functions for all decoded samples')

    def usage(self):
            print('usage: functions_all [-h][-r][-d]')

    def run(self):       
        super(Functions_All, self).run()
        if self.args is None:
            return               
                   
        # Get Viper's root path
        viper_path = get_viper_path(__project__.get_path())           
        
        # Retrieve all the samples from the database
        db = Database()
        samples = db.find(key='all')  
        
        if self.args.raw:  
            
            # Find functions for all samples
            count = 0
            success = 0
            for sample in samples:
                print(count)
                count += 1
                path = get_sample_path(sample.sha256)
                print(path)
                new_path = path + '(raw)(functions)'
     
                # Call the functions.php script and store its output   
                try:   
                    decoded = subprocess.check_output(['php', '-f', viper_path + '/modules/functions.php', path])        
                    f = open(new_path, 'w')        
                    f.write(decoded)          
                    f.close()
                    success += 1
                    print_success('Complete')
                except subprocess.CalledProcessError:
                    print_error('Failed to reach the functions.php script, please check if it exists in the modules folder')
                    
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
                
                # Find functions for all samples
                count = 0
                success = 0
                for sample in samples:
                    print(count)
                    count += 1
                    path = get_sample_path(sample.sha256) + '(decoded)'
                    print(path)
                    new_path = path + '(functions)'
            
                    # Call the functions.php script and store its output  
                    try:
                        decoded = subprocess.check_output(['php', '-f', viper_path + '/modules/functions.php', path])    
                        f = open(new_path, 'w')        
                        f.write(decoded)
                        f.close()
                        success += 1
                        print_success('Complete')
                    except subprocess.CalledProcessError:
                        print_error('Failed to reach the functions.php script, please check if it exists in the modules folder')
                        
                print_info(str(success) + ' samples were successfully processed')
                        
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()