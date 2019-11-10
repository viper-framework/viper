# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import logging
import logging.handlers

log = logging.getLogger('viper')

def init_logger(log_file_path="viper.log", debug=False):
    if debug:
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s")
    else:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    handler = logging.handlers.RotatingFileHandler(log_file_path, encoding='utf8',
        maxBytes=10000000, backupCount=1)
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)
    
    if debug:
        handler.setLevel(logging.DEBUG)
    
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    
    if debug:
        log.setLevel(logging.DEBUG)
    
    return log
