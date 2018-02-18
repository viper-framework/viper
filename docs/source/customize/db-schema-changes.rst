Making changes to the database schema
=====================================

Viper is using the framework Alembic (http://alembic.zzzcomputing.com/en/latest/) to support making
and deploying changes to the database schema. Refer to this tutorial forgetting a detail introduction
into why to use Alembic: http://alembic.zzzcomputing.com/en/latest/tutorial.html#running-our-first-migration

Configuration/Usage
===================

The **alembic.ini** file in the Viper root directory contains the URL to the database that will be used
when running the native alembic command line tools. Adapt it to your environment as needed (e.g. other
path/database type)::

    # this setting is used and needed for developers (e.g. when making changes)
    sqlalchemy.url = sqlite:///viper.db


Useful commands are::

    alembic current [--verbose]
    alembic history [--verbose]
    alembic heads [--verbose]
    alembic revision --autogenerate -m "Added account table"
    alembic upgrade head
    alembic downgrade -1

Please be aware that the autogeneration feature might not work perfectly in all cases!


A simple example
================

Let's assume you want to add another column to the *Malware* table. First update the class in database.py::

    diff --git a/viper/core/database.py b/viper/core/database.py
    index 1798871..a0633a5 100644
    --- a/viper/core/database.py
    +++ b/viper/core/database.py
    @@ -71,6 +71,7 @@ class Malware(Base):
         sha1 = Column(String(40), nullable=False)
         sha256 = Column(String(64), nullable=False, index=True)
         sha512 = Column(String(128), nullable=False)
    +    sha4711 = Column(String(47), nullable=True)
         ssdeep = Column(String(255), nullable=True)
         created_at = Column(DateTime(timezone=False), default=datetime.now(), nullable=False)
         parent_id = Column(Integer(), ForeignKey('malware.id'))


Then run the alembic revision command with the autogenerate flag a provide a short and meaning full message::

    alembic revision --autogenerate  -m "add sha4711 column"
    INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
    INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
    INFO  [alembic.autogenerate.compare] Detected added column 'malware.sha4711'
    Generating /home/viper/viper/alembic/versions/446173d7559f_add_sha4711_column.py ... done


The next steps is to check the generated file (viper/alembic/versions/446173d7559f_add_sha4711_column.py) and
if needed make adjustments. When the file is ok run the following to actually upgrade the database::

    alembic upgrade head
    INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
    INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
    INFO  [alembic.runtime.migration] Running upgrade 74c7becae858 -> 446173d7559f, add sha4711 column


The alembic history will now also show this revision::

    alembic history --verbose
    Rev: 446173d7559f (head)
    Parent: 74c7becae858
    Path: /home/viper/viper/viper/alembic/versions/446173d7559f_add_sha4711_column.py

    add sha4711 column

    Revision ID: 446173d7559f
    Revises: 74c7becae858
    Create Date: 2018-02-18 19:41:09.453930

    Rev: 74c7becae858
    Parent: <base>
    Path: /home/viper/viper/viper/alembic/versions/74c7becae858_initial_alembic_migration.py

    initial alembic migration

    Revision ID: 74c7becae858
    Revises:
    Create Date: 2017-05-09 20:52:15.401889


Make sure to include the new files in viper/alembic/versions/ in your git commits.


Viper is setup to automatically update user database if they are not running on the latest revision.
