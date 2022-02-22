from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Boolean, Integer, String

from dynamite_nsm import utilities

env = utilities.get_environment_file_dict()

SURICATA_CONFIGURATION = env.get('SURICATA_CONFIG')

engine = create_engine(f'sqlite:///{SURICATA_CONFIGURATION}/ruleset.db')
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Model = declarative_base(name='Model')


def init_ruleset_db():
    utilities.safely_remove_file(f'{SURICATA_CONFIGURATION}/ruleset.db')
    Model.metadata.create_all(bind=engine)


class Ruleset(Model):
    __tablename__ = 'ruleset'
    sid = Column('sid', Integer, primary_key=True)
    class_type = Column('class_type', String(254), index=True)
    lineno = Column('lineno', Integer)
    enabled = Column('enabled', Boolean)
    action = Column('action', String(12))
    proto = Column('proto', String(12))
    source = Column('source', String(2048))
    source_port = Column('source_port', String(2048))
    direction = Column('direction', String(2))
    destination = Column('destination', String(2048))
    destination_port = Column('destination_port', String(2048))
    options_blob = Column('options', String(4096))

    def __init__(self, sid: int, class_type: str, lineno: int, enabled: bool, action: str, proto: str, source: str,
                 source_port: str, direction: str, destination: str, destination_port: str, options_blob: str):
        self.sid = sid
        self.class_type = class_type
        self.lineno = lineno
        self.enabled = enabled
        self.action = action
        self.proto = proto
        self.source = source
        self.source_port = source_port
        self.direction = direction
        self.destination = destination
        self.destination_port = destination_port
        self.options_blob = options_blob


if __name__ == '__main__':
    init_ruleset_db()
