# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from __future__ import unicode_literals  # make all strings unicode in python2

import os
import json
import logging
from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy import Table, Index, create_engine, and_
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref, sessionmaker
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from viper.common.out import print_warning, print_error
from viper.common.objects import File
from viper.core.project import __project__
from viper.core.config import Config

log = logging.getLogger('viper')

cfg = Config()

Base = declarative_base()

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
        return "<Malware('{0}','{1}')>".format(self.id, self.md5)

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
    stored_at = Column(DateTime(timezone=False), default=datetime.now(), nullable=False)

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
    #__metaclass__ = Singleton

    def __init__(self):

        if hasattr(cfg, "database") and cfg.database.connection:
            self._connect_database(cfg.database.connection)
        else:
            self._connect_database("")

        self.engine.echo = False
        self.engine.pool_timeout = 60

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def __del__(self):
        self.engine.dispose()

    def _connect_database(self, connection):
        if connection.startswith("mysql+pymysql"):
            self.engine = create_engine(connection)
        elif connection.startswith("mysql"):
            self.engine = create_engine(connection, connect_args={"check_same_thread": False})
        elif connection.startswith("postgresql"):
            self.engine = create_engine(connection, connect_args={"sslmode": "disable"})
        else:
            db_path = os.path.join(__project__.get_path(), 'viper.db')
            self.engine = create_engine('sqlite:///{0}'.format(db_path), poolclass=NullPool)

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
                malware_entry.tag.append(Tag(tag))
                session.commit()
            except IntegrityError:
                session.rollback()
                try:
                    malware_entry.tag.append(session.query(Tag).filter(Tag.tag==tag).first())
                    session.commit()
                except SQLAlchemyError:
                    session.rollback()

    def list_tags(self):
        session = self.Session()
        rows = session.query(Tag).all()
        return rows

    def delete_tag(self, tag_name, sha256):
        session = self.Session()

        try:
            # First remove the tag from the sample
            malware_entry = session.query(Malware).filter(Malware.sha256 == sha256).first()
            tag = session.query(Tag).filter(Tag.tag==tag_name).first()
            try:
                malware_entry = session.query(Malware).filter(Malware.sha256 == sha256).first()
                malware_entry.tag.remove(tag)
                session.commit()
            except:
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

    def add_note(self, sha256, title, body):
        session = self.Session()

        malware_entry = session.query(Malware).filter(Malware.sha256 == sha256).first()
        if not malware_entry:
            return

        try:
            malware_entry.note.append(Note(title, body))
            session.commit()
        except SQLAlchemyError as e:
            print_error("Unable to add note: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def get_note(self, note_id):
        session = self.Session()
        note = session.query(Note).get(note_id)
        return note

    def edit_note(self, note_id, body):
        session = self.Session()

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
            rows = session.query(Malware).all()
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
            malware_entry.analysis.append(Analysis(cmd_line, results))
            session.commit()
        except SQLAlchemyError as e:
            print_error("Unable to store analysis: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def get_analysis(self, analysis_id):
        session = self.Session()
        analysis = session.query(Analysis).get(analysis_id)
        return analysis
