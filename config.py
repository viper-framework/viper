# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

##
# Viper
#


# Path to save Projects. 
# If None default is viper dir
project_path = None

# Path to save Main database and bins.
# If None default is viper dir
bin_path = None

# DataBase connection
# Examples
# sqlite:///foo.db
# postgresql://foo:bar@localhost:5432/mydatabase     -   sudo apt-get install python-psycopg2
# mysql://foo:bar@localhost/mydatabase     -   sudo apt-get insatll python-mysqldb
# If None, default is a SQLite in viper dir
db_conn = None

# API Web Port
api_port = 8080

##
# Module Configs
#

# VirusTotal
vt_key = 'a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088'

# Cuckoo
cuckoo_host = 'localhost'
cuckoo_port = '8090'

# Reports
MALWR_USER = None
MALWR_PASS = None
ANUBIS_USER = None
ANUBIS_PASS = None



