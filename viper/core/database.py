# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

from datetime import datetime

from sqlalchemy import *
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref, sessionmaker
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from viper.common.out import *
from viper.common.objects import File, Singleton

Base = declarative_base()

association_table = Table(
    'association',
    Base.metadata,
    Column('tag_id', Integer, ForeignKey('tag.id')),
    Column('malware_id', Integer, ForeignKey('malware.id'))
)

class Malware(Base):
    __tablename__ = 'malware'

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=True)
    size = Column(Integer(), nullable=False)
    type = Column(Text(), nullable=True)
    md5 = Column(String(32), nullable=False, index=True)
    crc32 = Column(String(8), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    sha512 = Column(String(128), nullable=False)
    ssdeep = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=False), default=datetime.now(), nullable=False)
    tag = relationship(
        'Tag',
        secondary=association_table,
        cascade='all, delete',
        backref=backref('malware', cascade='all')
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
        return "<Malware('%s','%s')>" % (self.id, self.md5)

    def __init__(self,
                 md5,
                 crc32,
                 sha1,
                 sha256,
                 sha512,
                 size,
                 type=None,
                 ssdeep=None,
                 name=None):
        self.md5 = md5
        self.sha1 = sha1
        self.crc32 = crc32
        self.sha256 = sha256
        self.sha512 = sha512
        self.size = size
        self.type = type
        self.ssdeep = ssdeep
        self.name = name

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
        return "<Tag ('%s','%s'>" % (self.id, self.tag)

    def __init__(self, tag):
        self.tag = tag

class Database:

    __metaclass__ = Singleton

    def __init__(self):
        self.engine = create_engine('sqlite:///viper.db', poolclass=NullPool)
        self.engine.echo = False
        self.engine.pool_timeout = 60

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def __del__(self):
        self.engine.dispose()

    def add_tags(self, sha256, tags):
        session = self.Session()

        malware_entry = session.query(Malware).filter(Malware.sha256 == sha256).first()
        if not malware_entry:
            return

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
            except IntegrityError as e:
                session.rollback()
                try:
                    malware_entry.tag.append(session.query(Tag).filter(Tag.tag==tag).first())
                    session.commit()
                except SQLAlchemyError:
                    session.rollback()

    def add(self, obj, name=None, tags=None):
        session = self.Session()

        if not name:
            name = obj.name

        if isinstance(obj, File):
            try:
                malware_entry = Malware(md5=obj.md5,
                                        crc32=obj.crc32,
                                        sha1=obj.sha1,
                                        sha256=obj.sha256,
                                        sha512=obj.sha512,
                                        size=obj.size,
                                        type=obj.type,
                                        ssdeep=obj.ssdeep,
                                        name=name)
                session.add(malware_entry)
                session.commit()
            except IntegrityError:
                session.rollback()
                malware_entry = session.query(Malware).filter(Malware.md5 == obj.md5).first()
            except SQLAlchemyError:
                session.rollback()
                return False

        if tags:
            self.add_tags(sha256=obj.sha256, tags=tags)

        return True

    def delete(self, id):
        session = self.Session()

        try:
            malware = session.query(Malware).get(id)
            session.delete(malware)
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            session.close()

        return True

    def find(self, key, value=None):
        session = self.Session()

        rows = None

        if not value:
            if key == 'all':
                rows = session.query(Malware).all()
            else:
                print_error("No valid term specified")
        else:
            if key == 'md5':
                rows = session.query(Malware).filter(Malware.md5 == value).all()
            elif key == 'sha256':
                rows = session.query(Malware).filter(Malware.sha256 == value).all()
            elif key == 'tag':
                rows = session.query(Malware).filter(Malware.tag.any(Tag.tag == value.lower())).all()
            elif key == 'name':
                if '*' in value:
                    value = value.replace('*', '%')
                else:
                    value = '%{0}%'.format(value)

                rows = session.query(Malware).filter(Malware.name.like(value)).all()
            else:
                print_error("No valid term specified")

        return rows

    def list_tags(self):
        session = self.Session()
        rows = session.query(Tag).all()
        return rows
 
    def list_latest_malware(self,value=None):
	if not value:
		value=5
        session = self.Session()
        rows = session.query(Malware).limit(value)
        return rows
