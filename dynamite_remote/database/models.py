from datetime import datetime

from sqlalchemy import DateTime, Column, Integer, String, ForeignKey
from dynamite_remote.database.db import Base


class NodeToGroupAssociation(Base):
    __tablename__ = 'node_to_group_association'
    id = Column(Integer(), primary_key=True, autoincrement=True)
    node_id = Column('node_id', Integer(), ForeignKey('nodes.id'))
    group_id = Column('group_id', Integer(), ForeignKey('groups.id'))


class Node(Base):
    __tablename__ = 'nodes'
    id = Column(Integer(), primary_key=True, autoincrement=True)
    name = Column('name', String(32), unique=True)
    host = Column('host', String(64), unique=True)
    port = Column('port', Integer())
    description = Column('description', String(255))
    invoke_count = Column('invoke_count', Integer(), default=0)
    last_invoked_at = Column(DateTime(), default=datetime.utcnow)


class NodeGroup(Base):
    __tablename__ = 'groups'
    id = Column(Integer(), primary_key=True, autoincrement=True)
    description = Column('description', String(255))

