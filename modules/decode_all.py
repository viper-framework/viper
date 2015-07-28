import subprocess

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.core.project import __project__
from viper.common.utils import get_viper_path

class Decode_All(Module):
    cmd = 'decode_all'
    description = 'Decodes all samples'

    def run(self):
        
        # Get Viper's root path
        viper_path = get_viper_path(__project__.get_path())
        
        # Retrieve all the samples from the database
        db = Database()
        samples = db.find(key='all')
        
        # Decode all samples
        count = 0
        success = 0
        for sample in samples:
            print(count)
            count += 1
            path = get_sample_path(sample.sha256)
            print(path)
       
            # Call the decode.php script and store its output   
            try:
                decoded = subprocess.check_output(['php', '-f', viper_path + '/modules/decode.php', path])        
                f = open(path + '(decoded)', 'w')        
                f.write(decoded)          
                f.close()
                success += 1
                print_success('Complete')
            except subprocess.CalledProcessError:
                print_error('Failed to reach the decode.php script, please check if it exists in the modules folder')      
             
        print_info(str(success) + ' samples were successfully processed')
