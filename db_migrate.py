## DB Migration tool 
import os
import sys
import shutil
import getpass
from sqlalchemy import *
from optparse import OptionParser

def rename_tables(project_name, db_path):
    # Connect
    print "  - Connecting to Viper Database {0}".format(db_path)
    engine = create_engine('sqlite:///{0}'.format(db_path))
    
    # Drop Indexes
    ix_list = ['ix_malware_md5', 'ix_malware_sha256', 'hash_index', 'ix_tag_tag']
    print "    - Dropping Indexes"
    for ix in ix_list:
        try:
            result = engine.execute('DROP INDEX IF EXISTS {0}'.format(ix))
        except Exception as e:
            print "    - ", e
        
    # Rename Tables
    sql_list = ['ALTER TABLE malware RENAME TO {0}_malware'.format(project_name),
                'ALTER TABLE note RENAME TO {0}_note'.format(project_name),
                'ALTER TABLE tag RENAME TO {0}_tag'.format(project_name),
                'ALTER TABLE association RENAME TO {0}_association'.format(project_name)
                ]
    print "    - Renaming Tables"
    for sql in sql_list:
        try:
            result = engine.execute(sql)
        except Exception as e:
            print "    - ", e
        
    # Create new Indexes
    new_ix_list = ['CREATE INDEX ix_{0}_malware_md5 ON {0}_malware (md5)'.format(project_name),
                   'CREATE INDEX ix_{0}_malware_sha256 ON {0}_malware (sha256)'.format(project_name),
                   'CREATE UNIQUE INDEX {0}_hash_index ON {0}_malware (md5, crc32, sha1, sha256, sha512)'.format(project_name),
                   'CREATE UNIQUE INDEX ix_{0}_tag_tag ON {0}_tag (tag)'.format(project_name)
                  ]
    print "    - Recreating Indexes"
    for ix in new_ix_list:
        try:
            result = engine.execute(ix)
        except Exception as e:
            print "    - ", e
            


def migrate_to_sqlite():
    print "Backing up Sqlite DB"
    
    try:
        shutil.copy('viper.db', 'viper.db.bak')
    except:
        cont = raw_input("Failed to Backup. Do you wish to continue? Y/n")
        if cont != 'Y':
            print "User stopped Migration"
            return
            
    print "Migrating Default Database"
    rename_tables('default', 'viper.db')

    print "Default Migrated"

    print "Migrating Projects"
    try:
        for project in os.listdir('projects'):
            print "Project - {0}".format(project)
            rename_tables(project, os.path.join('projects', project, 'viper.db'))
            print "{0} Migrated".format(project)
    except:
        print "Unable to find any projects, Passing"
        
    print "Migration Complete"


def migrate_to_mysql():
    print "Backing up Sqlite DB"
    
    try:
        shutil.copy('viper.db', 'viper.db.bak')
    except:
        cont = raw_input("Failed to Backup. Do you wish to continue? Y/n")
        if cont != 'Y':
            print "User stopped Migration"
            return
            
    sql_host = raw_input("MySQL Host Name: ")
    sql_user = raw_input("MySQL User Name: ")
    sql_pass = getpass.getpass()
    sql_name = raw_input("MySQL DB Name: ")
    
    
    project = 'default'
    db_path = 'viper.db'
    
    print "  - Connecting to Viper Database {0}".format(db_path)
    sqlite_engine = create_engine('sqlite:///{0}'.format(db_path))
    

    malware = sqlite_engine.execute('SELECT * FROM malware').fetchall()
    association = sqlite_engine.execute('SELECT * FROM association').fetchall()
    notes = sqlite_engine.execute('SELECT * FROM note').fetchall()
    tags = sqlite_engine.execute('SELECT * FROM tag').fetchall()
    
    
    print " - Connecting to MySQl Database"
    mysql_conn_string = 'mysql://{0}:{1}@{2}/{3}'.format(sql_user, sql_pass, sql_host, sql_name)
    mysql_engine = create_engine(mysql_conn_string)
    
    for row in malware:
        mysql_engine.execute("INSERT INTO {}_malware ('name', 'size', 'type', 'mime', 'md5', 'crc32', 'sha1', 'sha256', 'sha512', 'ssdeep', 'created_at') VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {} )".format(project, row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11]))
        
    for row in association:
        mysql_engine.execute("INSERT INTO {}_association ('tag_id', 'note_id', 'malware_id') VALUES ({}, {}, {})".format(project, row[0], row[1], row[2]))
        
    for row in notes:
        mysql_engine.execute("INSERT INTO {}_note ('title', 'body') VALUES ({0}, {1})".format(project, row[1], row[2]))
        
    for row in tags:
        mysql_engine.execute("INSERT INTO {}_tag ('tag') VALUES ({0})".format(project, row[1]))

    # Create new Indexes
    new_ix_list = ['CREATE INDEX ix_{0}_malware_md5 ON {0}_malware (md5)'.format(project),
                   'CREATE INDEX ix_{0}_malware_sha256 ON {0}_malware (sha256)'.format(project),
                   'CREATE UNIQUE INDEX {0}_hash_index ON {0}_malware (md5, crc32, sha1, sha256, sha512)'.format(project),
                   'CREATE UNIQUE INDEX ix_{0}_tag_tag ON {0}_tag (tag)'.format(project)
                  ]
    print "    - Recreating Indexes"
    for ix in new_ix_list:
        try:
            result = mysql_engine.execute(ix)
        except Exception as e:
            print "    - ", e







print "========================================================================="
print "| This script will migrate your Viper.db sqlite file to the new format. |"
print "| Please create a backup of this file before preceding.                 |"
print "| This script can also migrate to MySQL.                                |"
print "=========================================================================\n"

# Main
if __name__ == "__main__":
    parser = OptionParser(usage='usage: %prog ' )
    parser.add_option("-s", "--sqlite", action='store_true', default=False, help="Convert to New SQlite")
    parser.add_option("-m", "--mysql", action='store_true', default=False, help="Migrate to MySQL")
    parser.add_option("-c", "--confirm", action='store_true', default=False, help="Confirm Changes")
    
    (options, args) = parser.parse_args()

    if not options.confirm:
        print "You need to confirm changes with -c"
        sys.exit()
        
    if options.sqlite:
        print "Migrating to New SQlite format"
        migrate_to_sqlite()
        
    if options.mysql:
        print "Migrating to MySQL"
        print "To Migrate to MySQL follow these steps."
        print "1. Configure the Viper Config File to match your SQL Setup."
        print "2. Run Viper in order to create the initial tables"
        print "3. close viper and re run this command."
        confirm = raw_input("Have you completed the steps? Y/n")
        if confirm in ['Y', 'y']:
            migrate_to_mysql()






