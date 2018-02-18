# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import shutil
import sys
import json
import logging
from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy import Table, Index, MetaData, create_engine, and_

from sqlalchemy.pool import NullPool
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref, sessionmaker
from sqlalchemy.orm import subqueryload
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory

from viper.common.out import print_error, print_info, print_item, print_success, print_warning
from viper.common.exceptions import Python2UnsupportedUnicode
from viper.common.objects import File
from viper.core.storage import get_sample_path, store_sample
from viper.core.project import __project__
from viper.core.config import __config__


log = logging.getLogger('viper')

cfg = __config__

INITIAL_ALEMBIC_DB_REVISION = "74c7becae858"

Base = declarative_base()

# http://alembic.zzzcomputing.com/en/latest/naming.html
Base.metadata = MetaData(naming_convention={
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
})

association_table = Table(
    'association',
    Base.metadata,
    Column('tag_id', Integer, ForeignKey('tag.id')),
    Column('note_id', Integer, ForeignKey('note.id')),
    Column('malware_id', Integer, ForeignKey('malware.id')),
    Column('analysis_id', Integer, ForeignKey('analysis.id'))
)


class Malware(Base):
    __tablename__ = 'malware'

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=True)
    size = Column(Integer(), nullable=False)
    type = Column(Text(), nullable=True)
    mime = Column(String(255), nullable=True)
    md5 = Column(String(32), nullable=False, index=True)
    crc32 = Column(String(8), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    sha512 = Column(String(128), nullable=False)
    ssdeep = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=False), default=datetime.now(), nullable=False)
    parent_id = Column(Integer(), ForeignKey('malware.id'))
    parent = relationship('Malware', lazy='subquery', remote_side=[id])
    tag = relationship(
        'Tag',
        secondary=association_table,
        backref=backref('malware')
    )
    note = relationship(
        'Note',
        cascade='all, delete',
        secondary=association_table,
        backref=backref('malware')
    )
    analysis = relationship(
        'Analysis',
        cascade='all, delete',
        secondary=association_table,
        backref=backref('malware')
    )
    __table_args__ = (Index(
        'hash_index',
        'md5',
        'crc32',
        'sha1',
        'sha256',
        'sha512',
        unique=True
    ),)

    def to_dict(self):
        row_dict = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            row_dict[column.name] = value

        return row_dict

    def __repr__(self):
        return "<Malware ('{0}','{1}')>".format(self.id, self.md5)

    def __init__(self,
                 md5,
                 crc32,
                 sha1,
                 sha256,
                 sha512,
                 size,
                 type=None,
                 mime=None,
                 ssdeep=None,
                 name=None,
                 parent=None):
        self.md5 = md5
        self.sha1 = sha1
        self.crc32 = crc32
        self.sha256 = sha256
        self.sha512 = sha512
        self.size = size
        self.type = type
        self.mime = mime
        self.ssdeep = ssdeep
        self.name = name
        self.parent = parent


class Tag(Base):
    __tablename__ = 'tag'

    id = Column(Integer(), primary_key=True)
    tag = Column(String(255), nullable=False, unique=True, index=True)

    def to_dict(self):
        row_dict = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            row_dict[column.name] = value

        return row_dict

    def __repr__(self):
        return "<Tag ('{0}','{1}')>".format(self.id, self.tag)

    def __init__(self, tag):
        self.tag = tag


class Note(Base):
    __tablename__ = 'note'

    id = Column(Integer(), primary_key=True)
    title = Column(String(255), nullable=True)
    body = Column(Text(), nullable=False)

    def to_dict(self):
        row_dict = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            row_dict[column.name] = value

        return row_dict

    def __repr__(self):
        return "<Note ('{0}','{1}')>".format(self.id, self.title)

    def __init__(self, title, body):
        self.title = title
        self.body = body


class Analysis(Base):
    __tablename__ = 'analysis'

    id = Column(Integer(), primary_key=True)
    cmd_line = Column(String(255), nullable=True)
    results = Column(Text(), nullable=False)
    stored_at = Column(DateTime(timezone=False), default=datetime.utcnow, nullable=False)

    def to_dict(self):
        row_dict = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            row_dict[column.name] = value

        return row_dict

    def __repr__(self):
        return "<Analysis ('{0}','{1}')>".format(self.id, self.cmd_line)

    def __init__(self, cmd_line, results):
        self.cmd_line = cmd_line
        self.results = results


class Database:
    # __metaclass__ = Singleton

    def __init__(self):

        self.url = None
        self.type = None  # either sqlite, mysql or postgresql

        if cfg.database and cfg.database.connection:
            self._connect_database(cfg.database.connection)
        else:
            self._connect_database("")

        self.engine.echo = False
        self.engine.pool_timeout = 60

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

        if not check_database(self.url):
            upgrade_database(self.url, self.type, verbose=True)

        self.added_ids = {}
        self.copied_id_sha256 = []

    def __repr__(self):
        return "<{}>".format(self.__class__.__name__)

    def _connect_database(self, connection):
        self.url = connection
        if connection.startswith("mysql+pymysql"):
            self.type = "mysql"
            self.engine = create_engine(self.url)
        elif connection.startswith("mysql"):
            self.type = "mysql"
            self.engine = create_engine(self.url, connect_args={"check_same_thread": False})
        elif connection.startswith("postgresql"):
            self.type = "postgresql"
            self.engine = create_engine(self.url, connect_args={"sslmode": "disable"})
        else:
            self.type = "sqlite"
            db_path = os.path.join(__project__.get_path(), 'viper.db')
            self.url = 'sqlite:///{0}'.format(db_path)
            self.engine = create_engine(self.url, poolclass=NullPool)

    def add_tags(self, sha256, tags):
        session = self.Session()

        malware_entry = session.query(Malware).filter(Malware.sha256 == sha256).first()
        if not malware_entry:
            return

        # The tags argument might be a list, a single tag, or a
        # comma-separated list of tags.
        if isinstance(tags, str):
            tags = tags.strip()
            if ',' in tags:
                tags = tags.split(',')
            else:
                tags = tags.split()

        for tag in tags:
            tag = tag.strip().lower()
            if tag == '':
                continue

            try:
                new_tag = Tag(tag)
                malware_entry.tag.append(new_tag)
                session.commit()
                self.added_ids.setdefault("tag", []).append(new_tag.id)
            except IntegrityError:
                session.rollback()
                try:
                    malware_entry.tag.append(session.query(Tag).filter(Tag.tag == tag).first())
                    session.commit()
                except SQLAlchemyError:
                    session.rollback()

    def list_tags(self):
        session = self.Session()
        rows = session.query(Tag).all()
        return rows

    def list_tags_for_malware(self, sha256):
        session = self.Session()
        malware = session.query(Malware).options(subqueryload(Malware.tag)).filter(Malware.sha256 == sha256).first()
        return malware.tag

    def delete_tag(self, tag_name, sha256):
        session = self.Session()

        try:
            # First remove the tag from the sample
            malware_entry = session.query(Malware).filter(Malware.sha256 == sha256).first()
            tag = session.query(Tag).filter(Tag.tag == tag_name).first()
            try:
                malware_entry = session.query(Malware).filter(Malware.sha256 == sha256).first()
                malware_entry.tag.remove(tag)
                session.commit()
            except Exception:
                print_error("Tag {0} does not exist for this sample".format(tag_name))

            # If tag has no entries drop it
            count = len(self.find('tag', tag_name))
            if count == 0:
                session.delete(tag)
                session.commit()
                print_warning("Tag {0} has no additional entries dropping from Database".format(tag_name))
        except SQLAlchemyError as e:
            print_error("Unable to delete tag: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def list_notes(self):
        session = self.Session()
        rows = session.query(Note).all()
        return rows

    def add_note(self, sha256, title, body):
        session = self.Session()

        if sys.version_info < (3, 0):
            # on Python2 make sure to only handle ASCII
            try:
                title.decode('ascii')
                body.decode('ascii')
            except UnicodeError as err:
                raise Python2UnsupportedUnicode("Non ASCII character(s) in Notes not supported on Python2.\n"
                                                "Please use Python >= 3.4".format(err), "error")

        malware_entry = session.query(Malware).filter(Malware.sha256 == sha256).first()
        if not malware_entry:
            return

        try:
            new_note = Note(title, body)
            malware_entry.note.append(new_note)
            session.commit()
            self.added_ids.setdefault("note", []).append(new_note.id)
        except SQLAlchemyError as e:
            print_error("Unable to add note: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def get_note(self, note_id):
        session = self.Session()
        note = session.query(Note).get(note_id)

        if sys.version_info < (3, 0):
            # on Python2 make sure to only handle ASCII filenames
            try:
                note.title.decode('ascii')
                note.body.decode('ascii')
            except UnicodeError as err:
                raise Python2UnsupportedUnicode("Non ASCII character(s) in Notes not supported on Python2.\n"
                                                "Please use Python >= 3.4".format(err), "error")
        return note

    def edit_note(self, note_id, body):
        session = self.Session()

        if sys.version_info < (3, 0):
            # on Python2 make sure to only handle ASCII
            try:
                body.decode('ascii')
            except UnicodeError as err:
                raise Python2UnsupportedUnicode("Non ASCII character(s) in Notes not supported on Python2.\n"
                                                "Please use Python >= 3.4".format(err), "error")

        try:
            session.query(Note).get(note_id).body = body
            session.commit()
        except SQLAlchemyError as e:
            print_error("Unable to update note: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def delete_note(self, note_id):
        session = self.Session()

        try:
            note = session.query(Note).get(note_id)
            session.delete(note)
            session.commit()
        except SQLAlchemyError as e:
            print_error("Unable to delete note: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def add(self, obj, name=None, tags=None, parent_sha=None, notes_body=None, notes_title=None):
        session = self.Session()

        if not name:
            name = obj.name

        if parent_sha:
            parent_sha = session.query(Malware).filter(Malware.sha256 == parent_sha).first()

        if isinstance(obj, File):
            try:
                malware_entry = Malware(md5=obj.md5,
                                        crc32=obj.crc32,
                                        sha1=obj.sha1,
                                        sha256=obj.sha256,
                                        sha512=obj.sha512,
                                        size=obj.size,
                                        type=obj.type,
                                        mime=obj.mime,
                                        ssdeep=obj.ssdeep,
                                        name=name,
                                        parent=parent_sha)
                session.add(malware_entry)
                session.commit()
                self.added_ids.setdefault("malware", []).append(malware_entry.id)
            except IntegrityError:
                session.rollback()
                malware_entry = session.query(Malware).filter(Malware.md5 == obj.md5).first()
            except SQLAlchemyError as e:
                print_error("Unable to store file: {0}".format(e))
                session.rollback()
                return False

        if tags:
            self.add_tags(sha256=obj.sha256, tags=tags)

        if notes_body and notes_title:
            self.add_note(sha256=obj.sha256, title=notes_title, body=notes_body)

        return True

    def copy(self, id, src_project, dst_project,
             copy_analysis=True, copy_notes=True, copy_tags=True, copy_children=True, _parent_sha256=None):  # noqa
        session = self.Session()

        # make sure to open source project
        __project__.open(src_project)

        # get malware from DB
        malware = session.query(Malware). \
            options(subqueryload(Malware.analysis)). \
            options(subqueryload(Malware.note)). \
            options(subqueryload(Malware.parent)). \
            options(subqueryload(Malware.tag)). \
            get(id)

        # get path and load file from disk
        malware_path = get_sample_path(malware.sha256)
        sample = File(malware_path)
        sample.name = malware.name

        log.debug("Copying ID: {} ({}): from {} to {}".format(malware.id, malware.name, src_project, dst_project))
        # switch to destination project, add to DB and store on disk
        __project__.open(dst_project)
        dst_db = Database()
        dst_db.add(sample)
        store_sample(sample)
        print_success("Copied: {} ({})".format(malware.sha256, malware.name))

        if copy_analysis:
            log.debug("copy analysis..")
            for analysis in malware.analysis:
                dst_db.add_analysis(malware.sha256, cmd_line=analysis.cmd_line, results=analysis.results)

        if copy_notes:
            log.debug("copy notes..")
            for note in malware.note:
                dst_db.add_note(malware.sha256, title=note.title, body=note.body)

        if copy_tags:
            log.debug("copy tags..")
            dst_db.add_tags(malware.sha256, [x.tag for x in malware.tag])

        if copy_children:
            children = session.query(Malware).filter(Malware.parent_id == malware.id).all()
            if not children:
                pass
            else:
                _parent_sha256 = malware.sha256  # set current recursion item as parent
                for child in children:
                    self.copy(child.id,
                              src_project=src_project, dst_project=dst_project,
                              copy_analysis=copy_analysis, copy_notes=copy_notes, copy_tags=copy_tags,
                              copy_children=copy_children, _parent_sha256=_parent_sha256)
                    # restore parent-child relationships
                    log.debug("add parent {} to child {}".format(_parent_sha256, child.sha256))
                    if _parent_sha256:
                        dst_db.add_parent(child.sha256, _parent_sha256)

        # switch back to source project
        __project__.open(src_project)

        # store tuple of ID (in source project) and sha256 of copied samples
        self.copied_id_sha256.append((malware.id, malware.sha256))

        return True

    def rename(self, id, name):
        session = self.Session()

        if not name:
            return False

        try:
            malware = session.query(Malware).get(id)
            if not malware:
                print_error("The opened file doesn't appear to be in the database, have you stored it yet?")
                return False

            malware.name = name
            session.commit()
        except SQLAlchemyError as e:
            print_error("Unable to rename file: {}".format(e))
            session.rollback()
            return False
        finally:
            session.close()

        return True

    def delete_file(self, id):
        session = self.Session()

        try:
            malware = session.query(Malware).get(id)
            if not malware:
                print_error("The opened file doesn't appear to be in the database, have you stored it yet?")
                return False

            session.delete(malware)
            session.commit()
        except SQLAlchemyError as e:
            print_error("Unable to delete file: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()

        return True

    def find(self, key, value=None, offset=0):
        session = self.Session()
        offset = int(offset)
        rows = None

        if key == 'all':
            rows = session.query(Malware).options(subqueryload(Malware.tag)).all()
        elif key == 'ssdeep':
            ssdeep_val = str(value)
            rows = session.query(Malware).filter(Malware.ssdeep.contains(ssdeep_val)).all()
        elif key == 'any':
            prefix_val = str(value)
            rows = session.query(Malware).filter(Malware.name.startswith(prefix_val) |
                                                 Malware.md5.startswith(prefix_val) |
                                                 Malware.sha1.startswith(prefix_val) |
                                                 Malware.sha256.startswith(prefix_val) |
                                                 Malware.type.contains(prefix_val) |
                                                 Malware.mime.contains(prefix_val)).all()
        elif key == 'latest':
            if value:
                try:
                    value = int(value)
                except ValueError:
                    print_error("You need to specify a valid number as a limit for your query")
                    return None
            else:
                value = 5

            rows = session.query(Malware).order_by(Malware.id.desc()).limit(value).offset(offset)
        elif key == 'md5':
            rows = session.query(Malware).filter(Malware.md5 == value).all()
        elif key == 'sha1':
            rows = session.query(Malware).filter(Malware.sha1 == value).all()
        elif key == 'sha256':
            rows = session.query(Malware).filter(Malware.sha256 == value).all()
        elif key == 'tag':
            rows = session.query(Malware).filter(self.tag_filter(value)).all()
        elif key == 'name':
            if not value:
                print_error("You need to specify a valid file name pattern (you can use wildcards)")
                return None

            if '*' in value:
                value = value.replace('*', '%')
            else:
                value = '%{0}%'.format(value)

            rows = session.query(Malware).filter(Malware.name.like(value)).all()
        elif key == 'note':
            value = '%{0}%'.format(value)
            rows = session.query(Malware).filter(Malware.note.any(Note.body.like(value))).all()
        elif key == 'type':
            rows = session.query(Malware).filter(Malware.type.like('%{0}%'.format(value))).all()
        elif key == 'mime':
            rows = session.query(Malware).filter(Malware.mime.like('%{0}%'.format(value))).all()
        else:
            print_error("No valid term specified")

        return rows

    def tag_filter(self, value):
        if not value:
            return None
        if "|" in value and "&" in value:
            print_error("Do not use &' and '|' at the same time.")
            return None
        if "|" in value:
            filt = Malware.tag.any(Tag.tag.in_(value.lower().split("|")))
        elif "&" in value:
            tags = []
            for tt in value.lower().split("&"):
                tags.append(Malware.tag.any(Tag.tag == tt))
            filt = and_(*tags)
        else:
            filt = Malware.tag.any(Tag.tag == value.lower())
        return filt

    def get_sample_count(self):
        session = self.Session()
        return session.query(Malware.id).count()

    def add_parent(self, malware_sha256, parent_sha256):
        session = self.Session()

        try:
            malware = session.query(Malware).filter(Malware.sha256 == malware_sha256).first()
            malware.parent = session.query(Malware).filter(Malware.sha256 == parent_sha256).first()
            session.commit()
        except SQLAlchemyError as e:
            print_error("Unable to add parent: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def delete_parent(self, malware_sha256):
        session = self.Session()

        try:
            malware = session.query(Malware).filter(Malware.sha256 == malware_sha256).first()
            malware.parent = None
            session.commit()
        except SQLAlchemyError as e:
            print_error("Unable to delete parent: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def get_children(self, parent_id):
        session = self.Session()
        children = session.query(Malware).filter(Malware.parent_id == parent_id).all()
        child_samples = ''
        for child in children:
            child_samples += '{0},'.format(child.sha256)
        return child_samples

    # Store Module / Cmd Output
    def add_analysis(self, sha256, cmd_line, results):
        results = json.dumps(results)
        session = self.Session()

        malware_entry = session.query(Malware).filter(Malware.sha256 == sha256).first()
        if not malware_entry:
            return
        try:
            new_analysis = Analysis(cmd_line, results)
            malware_entry.analysis.append(new_analysis)
            session.commit()
            self.added_ids.setdefault("analysis", []).append(new_analysis.id)
        except SQLAlchemyError as e:
            print_error("Unable to store analysis: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def get_analysis(self, analysis_id):
        session = self.Session()
        analysis = session.query(Analysis).get(analysis_id)
        return analysis

    def list_analysis(self):
        session = self.Session()
        rows = session.query(Analysis).all()
        return rows


def backup_database(database_url, sqlite=True, verbose=False):
    # for sqlite a DB backup is easy (just copy the file)
    if sqlite:
        if not database_url.startswith('sqlite:///'):
            raise Exception("Malformed sqlite database URL (should start with sqlite:///): {}".format(database_url))

        # get path from url (for backup)
        database_path = database_url[10:]  # strip sqlite:/// to get path

        # backup of database name with a timestamp to avoid it to be overwritten
        db_dir = os.path.dirname(database_path)
        db_backup_path = os.path.join(db_dir, "viper_db_backup_{0}.db".format(datetime.utcnow().strftime("%Y%m%d-%H%M%S")))
        if verbose:
            print_item("Backing up Sqlite DB to: {}".format(db_backup_path))

        try:
            shutil.copy(database_path, db_backup_path)
        except Exception as e:
            print_error("Failed to Backup. {0} Stopping".format(e))
            return

    else:
        print_info("Skipping DB backup for non sqlite DB (e.g. MariaDB/PostgreSQL)")


# SQLAlchemy/Alembic database migration (update)
def _migrate_db_to_alembic_management(db_url, db_type, rev, alembic_cfg=None, engine=None, verbose=False):
    """ migrate a non alembic database to a specified revision

    :param db: viper.core.database.Database object
    :type db: viper.core.database.Database
    :param rev: Alembic revision string which should be used
    :type rev: String
    :param alembic_cfg: configured AlembicConfig instance
    :type alembic_cfg: object
    :param engine: connected SQL Alchemy engine instance
    :type engine: object
    :param verbose: If True, print more status messages
    :type verbose: Boolean
    """

    if not alembic_cfg:
        # set URL and setup Alembic config
        alembic_cfg = AlembicConfig()
        alembic_cfg.set_main_option("script_location", "viper:alembic")
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    if not engine:
        # setup SQLAlchemy engine and connect to db
        engine = create_engine(db_url)

    if verbose:
        print_item("Reading data from Database")
    log.debug("Reading data from Database")

    malware = engine.execute('SELECT * FROM malware').fetchall()
    analysis = engine.execute('SELECT * FROM analysis').fetchall()
    association = engine.execute('SELECT * FROM association').fetchall()
    notes = engine.execute('SELECT * FROM note').fetchall()
    tags = engine.execute('SELECT * FROM tag').fetchall()

    validation_check = True
    try:
        log.debug("# cols malware: {}".format(len(malware[0])))
        if not len(malware[0]) == 13:
            validation_check = False
    except IndexError:
        log.debug("# cols malware: no rows")

    try:
        log.debug("# cols analysis: {}".format(len(analysis[0])))
        if not len(analysis[0]) == 4:
            validation_check = False
    except IndexError:
        log.debug("# cols analysis: no rows")

    try:
        log.debug("# cols association: {}".format(len(association[0])))
        if not len(association[0]) == 4:
            validation_check = False
    except IndexError:
        log.debug("# cols association: no rows")

    try:
        log.debug("# cols notes: {}".format(len(notes[0])))
        if not len(notes[0]) == 3:
            validation_check = False
    except IndexError:
        log.debug("# cols notes: no rows")

    try:
        log.debug("# cols tags: {}".format(len(tags[0])))
        if not len(tags[0]) == 2:
            validation_check = False
    except IndexError:
        log.debug("# cols tags: no rows")

    if validation_check:
        log.debug("successfully validated old DB schema")
    else:
        log.debug("failed to validated old DB schema")
        print_error("Unsupported DB state - Exiting!")
        sys.exit(1)

    if verbose:
        print_item("Dropping tables from Database")

    if db_type == "sqlite":
        engine.execute("DROP TABLE analysis;")
        engine.execute("DROP TABLE note;")
        engine.execute("DROP TABLE tag;")
        engine.execute("DROP TABLE association;")
        engine.execute("DROP TABLE malware;")
    elif db_type == "mysql":
        pass  # TODO(frennkie) implement this
    elif db_type == "postgresql":
        engine.execute("DROP TABLE malware CASCADE;")
        engine.execute("DROP TABLE association CASCADE;")
        engine.execute("DROP TABLE analysis CASCADE;")
        engine.execute("DROP TABLE note CASCADE;")
        engine.execute("DROP TABLE tag CASCADE;")
    else:
        pass

    # re-create tables according to initial rev schema
    if verbose:
        print_item("Creating initial schema in Database (Revision: {})".format(rev))
    command.upgrade(alembic_cfg, rev)

    if verbose:
        print_item("Inserting data back into Database")

    # Add all the rows back in
    for row in analysis:
        engine.execute("INSERT INTO analysis VALUES ('{0}', '{1}', '{2}', '{3}')".format(row[0], row[1], row[2], row[3]))

    for row in notes:
        engine.execute("INSERT INTO note VALUES ('{0}', '{1}', '{2}')".format(row[0], row[1], row[2]))

    for row in tags:
        engine.execute("INSERT INTO tag VALUES ('{0}', '{1}')".format(row[0], row[1]))

    for row in malware:
        engine.execute("INSERT INTO malware VALUES ("
                       "'{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', "
                       "'{7}', '{8}', '{9}', '{10}', '{11}', '{12}'"
                       ")".format(row[0], row[1], row[2], row[3], row[4], row[5], row[6],
                                  row[7], row[8], row[9], row[10], row[11], row[12]))

    # Rebuild association table with foreign keys
    for row in association:
        if row[0] is None:
            tag_id = "Null"
        else:
            tag_id = "(SELECT id from tag WHERE id='{0}')".format(row[0])
        if row[1] is None:
            note_id = "Null"
        else:
            note_id = "(SELECT id from note WHERE id='{0}')".format(row[1])
        if row[2] is None:
            malware_id = "Null"
        else:
            malware_id = "(SELECT id from malware WHERE id='{0}')".format(row[2])

        if row[3] is None:
            analysis_id = "Null"
        else:
            analysis_id = "(SELECT id from analysis WHERE id='{0}')".format(row[3])

        engine.execute("INSERT INTO association VALUES ({0}, {1}, {2}, {3})".format(tag_id, note_id, malware_id, analysis_id))


def _is_alembic_enabled(engine):
    context = MigrationContext.configure(engine.connect())
    if context.get_current_revision():
        return True
    else:
        return False


def _is_alembic_up2date_with_rev(engine, rev):
    context = MigrationContext.configure(engine.connect())
    if context.get_current_revision() == rev:
        return True
    else:
        return False


def _get_current_script_head(alembic_cfg):
    # set URL and setup Alembic config
    script = ScriptDirectory.from_config(alembic_cfg)
    return script.get_current_head()


def check_database(database_url):
    # set URL and setup Alembic config
    alembic_cfg = AlembicConfig()
    alembic_cfg.set_main_option("script_location", "viper:alembic")
    alembic_cfg.set_main_option("sqlalchemy.url", database_url)

    engine = create_engine(database_url)
    if not _is_alembic_enabled(engine):
        return False

    current_head = _get_current_script_head(alembic_cfg)
    if not _is_alembic_up2date_with_rev(engine, current_head):
        return False

    return True


def upgrade_database(db_url, db_type, create_backup=True, verbose=False):
    if check_database(db_url):
        print_info("Already up2date!")
        return

    if create_backup:
        if db_type == "sqlite":
            backup_database(db_url, sqlite=True, verbose=verbose)
        else:
            backup_database(db_url, sqlite=False, verbose=verbose)

    # set URL and setup Alembic config
    alembic_cfg = AlembicConfig()
    alembic_cfg.set_main_option("script_location", "viper:alembic")
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    # setup SQLAlchemy engine and connect to db
    if verbose:
        print_item("Connecting to Viper Databases: {}".format(db_url))
    engine = create_engine(db_url)

    if not _is_alembic_enabled(engine):
        log.warning("Database ({}) has never seen an Alembic migration".format(db_url))
        if verbose:
            print_warning("Database ({}) has never seen an Alembic migration".format(db_url))

        # migrate to initial alembic revision for Viper
        _migrate_db_to_alembic_management(db_url, db_type, INITIAL_ALEMBIC_DB_REVISION, alembic_cfg, engine, verbose=verbose)

    else:
        log.debug("is_alembic_enabled: True")

    current_head = _get_current_script_head(alembic_cfg)
    if _is_alembic_up2date_with_rev(engine, current_head):
        log.debug("is_alembic_up2date_with_rev (Rev: {}): True".format(current_head))
        if verbose:
            print_item("Database is now up-to-date".format(current_head))

    else:
        log.debug("is_alembic_up2date_with_rev (Rev: {}): False".format(current_head))

        log.info("Migrating to head ({})".format(current_head))
        if verbose:
            print_warning("Migrating to head ({})".format(current_head))
        command.upgrade(alembic_cfg, current_head)

    if verbose:
        print_success("DB update finished successfully")
