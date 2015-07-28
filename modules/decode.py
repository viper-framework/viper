import subprocess

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.project import __project__
from viper.common.utils import get_viper_path

class Decode(Module):
    cmd = 'decode'
    description = 'Reveals code hidden by eval() or preg_replace() constructs'

    def run(self):
        
        # Check for an open session
        if not __sessions__.is_set():
            print_error('No session opened')
            return
         
        # Get Viper's root path
        viper_path = get_viper_path(__project__.get_path())
    
        # Get the file path for use by the decode.php script
        path = __sessions__.current.file.path
	print(path)
        
        # Call the decode.php script and store its output
        try:
            output = subprocess.check_output(['php', '-f', viper_path + '/modules/decode.php', path])
            f = open(path + '(decoded)', 'w')  
            f.write(output)          
            f.close()
            print(output)
            print_success('Complete')
        except subprocess.CalledProcessError:
            print_error('Failed to reach the decode.php script, please check if it exists in the modules folder')       

           
