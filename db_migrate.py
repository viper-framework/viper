## DB Migration tool 
import os
from sqlalchemy import *

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
print "========================================================================="
print "| This script will migrate your Viper.db sqlite file to the new format. |"
print "| Please create a backup of this file before preceding                  |"
print "=========================================================================\n"

accept = raw_input("Do you want to migrate viper and its projects?\nEnter YES to accept\n")

if accept == 'YES':

    print "Migrating Default Database"
    rename_tables('default', 'viper.db')

    print "Default Migrated"

    print "Migrating Projects"
    for project in os.listdir('projects'):
        print "Project - {0}".format(project)
        rename_tables(project, os.path.join('projects', project, 'viper.db'))
        print "{0} Migrated".format(project)
        
    print "Migration Complete"
else:
    print "Not Migrating"
