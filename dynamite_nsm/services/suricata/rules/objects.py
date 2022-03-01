from __future__ import annotations

import os.path
import re
from random import randint
from typing import Dict, List, Optional, Tuple, Union

import sqlalchemy.exc
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Boolean, Integer, String
from sqlalchemy.orm import scoped_session, sessionmaker

from dynamite_nsm import utilities
from dynamite_nsm.services.suricata.rules import validators
from dynamite_nsm.services.base.config import GenericConfigManager

env = utilities.get_environment_file_dict()

SURICATA_CONFIGURATION = env.get('SURICATA_CONFIG')
Model = declarative_base(name='Model')


class MissingSid(Exception):
    def __init__(self):
        msg = f"This rule is missing an 'sid'."
        super(MissingSid, self).__init__(msg)


class InvalidRule(Exception):
    def __init__(self, sid, msg):
        msg = f"SID: {sid} is invalid: {msg}."
        super(InvalidRule, self).__init__(msg)


class MissingRule(Exception):
    def __init__(self, sid):
        msg = f"Rule with SID: {sid} does not exist."
        super(MissingRule, self).__init__(msg)


def parse_suricata_rule_options_blob(opts: str) -> List[Union[Tuple, str]]:
    """Parses the options section of Suricata Rules
    Args:
        opts: A valid set of ";" separated options

    Returns:
        A List of options
    """
    options = []

    # split by ; excluding those found inside quotations
    tokenized_opts = re.split(r";(?![(\"]*[\")])", opts)
    for opt in tokenized_opts:
        opt = opt.strip()
        if not opt:
            continue
        tokenized_opt = opt.split(':')
        if opt.startswith('pcre:'):
            k = tokenized_opt[0]
            v = opt[5:]
            options.append((k, v))
        elif len(tokenized_opt) == 2:
            k, v = tokenized_opt
            v = v.replace(';', '')
            options.append((k, v))
        elif len(tokenized_opt) == 1:
            options.append(tokenized_opt[0].replace(';', ''))
        else:
            k = tokenized_opt[0]
            v = ':'.join(tokenized_opt[1:])
            options.append((k, v))
    return options


def serialize_suricata_rule(rule: str) -> Rule:
    """Convert a plaintext Suricata rule into a Rule object
    Args:
        rule: A plaintext Suricata rule

    Returns:
        A Suricata Rule object

    """
    enabled = True
    if rule.startswith('#'):
        enabled = False
        rule = rule[1:].strip()
    o_paren_index = rule.index('(') + 1
    c_paren_index = max([i for i, c in enumerate(rule) if c == ')'])
    action_header = re.sub(r'\s+', ' ', rule[0: o_paren_index - 1]).strip()
    rule_options = rule[o_paren_index:c_paren_index]
    action = action_header.split(' ')[0].strip()
    header = action_header.replace(action, '').strip()
    header_proto = header.split(' ')[0].strip()
    header_source = header.split(' ')[1].strip()
    header_source_port = header.split(' ')[2].strip()
    header_direction = header.split(' ')[3].strip()
    header_destination = header.split(' ')[4].strip()
    header_destination_port = header.split(' ')[5].strip()
    options = parse_suricata_rule_options_blob(rule_options)
    return Rule(enabled, action, header_proto, header_source, header_source_port, header_direction, header_destination,
                header_destination_port, options)


class Rule:

    def __init__(self, enabled: bool, action: str, proto: str, source: str, source_port: str, direction: str,
                 destination: str, destination_port: str, options: List):
        extracted_options = self.extract_options(options)
        self.sid = extracted_options.get('sid')
        self.class_type = extracted_options.get('class_type')
        self.enabled = enabled
        self.action = action
        self.proto = proto
        self.source = source
        self.source_port = source_port
        self.direction = direction
        self.destination = destination
        self.destination_port = destination_port
        self.options = options

    def __str__(self):
        enabled = '#' if not self.enabled else ''
        return f'{enabled}{self.action} {self.proto} {self.source} {self.source_port} {self.direction} ' \
               f'{self.destination} {self.destination_port} ({self.options_blob()})'

    @classmethod
    def create_from_ruleset_entry(cls, ruleset: Ruleset) -> Rule:
        """Create an instance of this class using `models.Ruleset` entry
        Args:
            ruleset: A `models.Ruleset` instance

        Returns:
            An instance of this class
        """
        return Rule(enabled=ruleset.enabled,
                    action=ruleset.action,
                    proto=ruleset.proto,
                    source=ruleset.source,
                    source_port=ruleset.source_port,
                    direction=ruleset.direction,
                    destination=ruleset.destination,
                    destination_port=ruleset.destination_port,
                    options=parse_suricata_rule_options_blob(ruleset.options_blob)
                    )

    @staticmethod
    def generate_sid():
        return randint(10 ** 5, 10 ** 6)

    @staticmethod
    def extract_options(options: List) -> Dict:
        """Parse out the required sid and classtype fields from given options
        Returns:
            The SID of the rule.
        """
        key_val_opts = dict([opt for opt in options if isinstance(opt, tuple)])
        sid = key_val_opts.get('sid')
        if not sid:
            sid = Rule.generate_sid()
        class_type = key_val_opts.get('classtype')
        if not class_type:
            class_type = 'unknown'
        return dict(sid=sid, class_type=class_type)

    def compare(self, rule: Rule):
        if self.action != rule.action:
            return False
        elif self.source != rule.source:
            return False
        elif self.source_port != rule.source_port:
            return False
        elif self.direction != rule.direction:
            return False
        elif self.destination != rule.destination:
            return False
        elif self.destination_port != rule.destination_port:
            return False
        elif self.options != rule.options:
            return False
        return True

    def header(self) -> str:
        """Retrieve the rule header
        Returns:
            The rule header (E.G tcp 192.168.0.5 any -> 192.168.0.13 3389)
        """
        return f'{self.action} {self.proto} {self.source} {self.source_port} {self.direction} {self.destination_port}'

    def options_blob(self) -> str:
        """Retrieve the rule options as a string
        Returns:
            A String representation of the rule options
        """
        options = []
        found_sid = False
        found_class_type = False
        for opt in self.options:
            if isinstance(opt, tuple):
                k, v = opt
                # PCRE options have lots of string literals that often need to be escaped
                if k.lower() == 'pcre':
                    # repr function attempts to escape single quote characters which is not what we want as all pcre
                    # options are encapsulated in double quotes.
                    v = v.replace("'", "singlequotechar")
                    v = repr(v)[1:-1]
                    v = v.replace('singlequotechar', "'")
                    # replace double backslashes with single backslashes
                    v = v.replace('\\\\', '\\')
                elif k.lower() == 'sid':
                    v = self.sid
                    found_sid = True
                elif k.lower() == 'classtype':
                    v = self.class_type
                    found_class_type = True
                options.append(f'{k}:{v}')
            elif isinstance(opt, str):
                options.append(opt)
        if not found_class_type:
            options.append(f'classtype:{self.class_type}')
        if not found_sid:
            options.append(f'sid:{self.sid}')
        return '; '.join(options) + ';'

    def validate(self) -> Dict:
        """Determine if the rule is valid, and return metadata associated with it
        Returns:
            A dictionary containing the sid, options count, and rule character count
        """
        if not validators.validate_suricata_address_group_values(self.source):
            raise InvalidRule(sid=self.sid, msg=f'source is invalid: {self.source}')
        elif not validators.validate_suricata_port_group_values(self.source_port):
            raise InvalidRule(sid=self.sid, msg=f'source_port is invalid: {self.source_port}')
        elif not validators.validate_suricata_address_group_values(self.destination):
            raise InvalidRule(sid=self.sid, msg=f'destination is invalid: {self.destination}')
        if not validators.validate_suricata_port_group_values(self.destination_port):
            raise InvalidRule(sid=self.sid, msg=f'destination_port is invalid: {self.destination_port}')
        return {
            'enabled': self.enabled,
            'sid': self.sid,
            'class_type': self.class_type,
            'options': len(self.options),
            'characters': len(self.__str__())
        }


class Ruleset(Model):
    __tablename__ = 'ruleset'
    id = Column('id', Integer, primary_key=True, autoincrement=True, nullable=False)
    sid = Column('sid', Integer, unique=True, index=True)
    class_type = Column('class_type', String(254), index=True)
    lineno = Column('lineno', Integer, index=True)
    lineos = Column('lineos', Integer, index=True)
    enabled = Column('enabled', Boolean)
    action = Column('action', String(12))
    proto = Column('proto', String(12))
    source = Column('source', String(2048))
    source_port = Column('source_port', String(2048))
    direction = Column('direction', String(2))
    destination = Column('destination', String(2048))
    destination_port = Column('destination_port', String(2048))
    options_blob = Column('options', String(4096))

    def __init__(self, sid: int, class_type: str, lineno: int, lineos: int, enabled: bool, action: str, proto: str,
                 source: str, source_port: str, direction: str, destination: str, destination_port: str,
                 options_blob: str):
        self.sid = sid
        self.class_type = class_type
        self.lineno = lineno
        self.lineos = lineos
        self.enabled = enabled
        self.action = action
        self.proto = proto
        self.source = source
        self.source_port = source_port
        self.direction = direction
        self.destination = destination
        self.destination_port = destination_port
        self.options_blob = options_blob

    @classmethod
    def create_from_rule(cls, rule: Rule, sid: Optional[int] = None, lineno: Optional[int] = -1,
                         lineos: Optional[int] = -1) -> Ruleset:
        if sid:
            rule.sid = sid

        return cls(
            sid=rule.sid,
            class_type=rule.class_type,
            enabled=rule.enabled,
            action=rule.action,
            proto=rule.proto,
            source=rule.source,
            source_port=rule.source_port,
            direction=rule.direction,
            destination=rule.destination,
            destination_port=rule.destination_port,
            options_blob=rule.options_blob(),
            lineno=lineno,
            lineos=lineos,
        )


class RuleFile(GenericConfigManager):

    def __init__(self, rule_file_path: str):
        self._idx = 1
        super().__init__({}, 'suricata.rules.manager')
        first_init = False
        db_path = f"{SURICATA_CONFIGURATION}/{os.path.basename(rule_file_path).replace('.rules', '.db')}"
        if not os.path.exists(db_path):
            first_init = True
        self.cache_path = db_path
        self.engine = create_engine(f'sqlite:///{self.cache_path}')
        self.db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=self.engine))
        self.rule_file_path = rule_file_path
        self.suricata_configuration_root = env['SURICATA_CONFIG']
        if first_init:
            self.logger.info('First init detected, building cache.')
            self.build_cache()

    def __iter__(self):
        return self

    def __next__(self):
        _raw = self.db_session.query(Ruleset).get(self._idx)
        self._idx += 1
        if not _raw:
            raise StopIteration()
        return Rule.create_from_ruleset_entry(_raw)

    def init_cache(self):
        utilities.safely_remove_file(self.cache_path)
        Model.metadata.create_all(bind=self.engine)

    def build_cache(self):
        self.init_cache()
        with open(self.rule_file_path, 'r') as rule_file_in:
            lineno = 1
            while True:
                line = rule_file_in.readline()
                if line == '':
                    break
                rule = serialize_suricata_rule(line)
                if not validators.validate_suricata_address_group_values(rule.source):
                    self.logger.warning(f'{rule.sid} source ({rule.source}) is not valid.')
                elif not validators.validate_suricata_port_group_values(rule.source_port):
                    self.logger.warning(f'{rule.sid} source_port ({rule.source_port}) is not valid.')
                elif not validators.validate_suricata_address_group_values(rule.destination):
                    self.logger.warning(f'{rule.sid} destination ({rule.destination}) is not valid.')
                elif not validators.validate_suricata_port_group_values(rule.destination_port):
                    self.logger.warning(f'{rule.sid} destination_port ({rule.destination_port}) is not valid.')

                rs = Ruleset(
                    sid=rule.sid,
                    class_type=rule.class_type,
                    lineno=lineno + 1,
                    lineos=rule_file_in.tell(),
                    enabled=rule.enabled,
                    action=rule.action,
                    proto=rule.proto,
                    source=rule.source,
                    source_port=rule.source_port,
                    direction=rule.direction,
                    destination=rule.destination,
                    destination_port=rule.destination_port,
                    options_blob=rule.options_blob()
                )
                self.db_session.add(rs)
                lineno += 1
            self.db_session.commit()

    def get_rule(self, sid: int) -> Optional[Rule]:
        """Given the sid for a cached rule, returns the corresponding `Rule` instance
        Args:
            sid: The sid of the rule to fetch

        Returns:
            A `Rule` instance
        """
        self.logger.debug(f'Fetching rule {sid}.')
        rule_record = self.db_session.query(Ruleset).filter_by(sid=sid).one()
        if rule_record:
            return Rule(
                enabled=rule_record.enabled,
                action=rule_record.action,
                proto=rule_record.proto,
                source=rule_record.source,
                source_port=rule_record.source_port,
                direction=rule_record.direction,
                destination=rule_record.destination,
                destination_port=rule_record.destination_port,
                options=parse_suricata_rule_options_blob(rule_record.options_blob)
            )
        raise MissingRule(sid)

    def add_rule(self, new_rule: Rule) -> None:
        """Add a new custom rule
        Args:
            new_rule: A `Rule` instance
        Returns:
            None
        """
        new_rule.validate()
        self.logger.debug(f'Adding rule {new_rule.sid} -> {new_rule}')
        with open(f'{self.suricata_configuration_root}/.deltas', 'a') as deltas_f_out:
            deltas_f_out.write(
                f'{new_rule.sid},add,{new_rule}\n'
            )

    def delete_rule(self, sid: int) -> None:
        """Remove a custom rule if it was previously added via the `add_rule` method.
        Args:
            sid: The sid of the rule to delete
        Returns:
            None
        """
        new_content = ''
        with open(f'{self.suricata_configuration_root}/.deltas', 'r') as deltas_f_in:
            for line in deltas_f_in.readlines():
                line_tokens = line.split(',')
                parsed_sid = line_tokens[0]
                if parsed_sid.strip() == str(sid):
                    new_content += f'{sid},delete\n'
                else:
                    new_content += f'{line.strip()}\n'

        with open(f'{self.suricata_configuration_root}/.deltas', 'w') as deltas_f_out:
            deltas_f_out.write(new_content)

    def disable_rule(self, sid: int) -> None:
        """Disable a rule
        Args:
            sid: The sid of the rule to enable
        Returns:
            None
        """
        self.get_rule(sid)
        with open(f'{self.suricata_configuration_root}/.deltas', 'a') as deltas_f_out:
            deltas_f_out.write(
                f'{sid},disable\n'
            )

    def enable_rule(self, sid: int) -> None:
        """Enable a rule
        Args:
            sid: The sid of the rule to enable
        Returns:
            None
        """
        self.get_rule(sid)
        with open(f'{self.suricata_configuration_root}/.deltas', 'a') as deltas_f_out:
            deltas_f_out.write(
                f'{sid},enable\n'
            )

    def edit_rule(self, sid: int, new_rule: Rule) -> None:
        """Replace an existing rule with a new one
        Args:
            sid: The sid of the rule to delete
            new_rule: A `Rule` instance
        Returns:
            None
        """
        new_rule.sid = sid
        self.get_rule(sid)
        new_rule.validate()
        self.logger.debug(f'Editing rule {new_rule.sid} -> {new_rule}')
        with open(f'{self.suricata_configuration_root}/.deltas', 'a') as deltas_f_out:
            deltas_f_out.write(
                f'{new_rule.sid},edit,{new_rule}\n'
            )

    def merge(self):
        change_set_map = {}
        with open(f'{self.suricata_configuration_root}/.deltas', 'r') as deltas_f_in:
            # Loop through the .deltas file and parse out the sid, action, and data
            # Create a change_set_map that maps a rule sid to the actions to perform on that rule
            # {sid: [(action, data), ...]}
            for line in deltas_f_in.readlines():
                tokenized_line = line.split(',')
                sid = tokenized_line[0]
                action = tokenized_line[1]
                data = ','.join(tokenized_line[2:]).strip()
                if not change_set_map.get(sid):
                    change_set_map[sid] = [(action, data)]
                else:
                    change_set_map[sid].append((action, data))

        # Loop through change_set_map, each iteration will inspect a rule mapped to one or more changes.
        # Changes are applied to the database in order.
        for sid, changes in change_set_map.items():
            # Loop through all the changes that are applied to a particular rule
            for change in changes:
                action, data = change
                action, data = action.strip(), data.strip()

                # Add the rule to our ruleset database cache.
                if action == 'add':
                    self.logger.info(f'Adding {sid} -> {data} to cache.')
                    rule = serialize_suricata_rule(data)
                    rs = Ruleset.create_from_rule(rule, sid=int(sid))
                    self.db_session.add(rs)
                    try:
                        self.db_session.commit()
                    except sqlalchemy.exc.IntegrityError as e:
                        if 'UNIQUE constraint failed' in str(e):
                            self.db_session.rollback()
                            self.logger.info(f'{sid} already exists in the cache, skipping add.')

                # Remove the rule from our ruleset database cache.
                elif action == 'delete':
                    self.logger.info(f'Deleting {sid} from cache.')
                    ruleset = self.db_session.query(Ruleset).get(sid)
                    if ruleset:
                        self.db_session.delete(ruleset)
                        self.db_session.commit()
                    else:
                        self.logger.info(f'{sid} does not exists in the cache, skipping delete.')
                elif action == 'disable':
                    self.logger.info(f'Disabling {sid} in cache.')
                    ruleset = self.db_session.query(Ruleset).get(sid)
                    if ruleset:
                        ruleset.enabled = False
                        self.db_session.commit()
                    else:
                        self.logger.info(f'{sid} does not exists in the cache, skipping disable.')
                elif action == 'enable':
                    self.logger.info(f'Enabling {sid} in cache.')
                    ruleset = self.db_session.query(Ruleset).get(sid)
                    if ruleset:
                        ruleset.enabled = True
                        self.db_session.commit()
                    else:
                        self.logger.info(f'{sid} does not exists in the cache, skipping enable.')
                elif action == 'edit':
                    self.logger.info(f'Editing {sid} in cache.')
                    rule = serialize_suricata_rule(data)
                    ruleset = self.db_session.query(Ruleset).get(sid)
                    if rule.action != ruleset.action:
                        self.logger.debug(f'Updating action {ruleset.action} -> {rule.action}')
                        ruleset.action = rule.action
                    if rule.enabled != ruleset.enabled:
                        self.logger.debug(f'Updating enabled {ruleset.enabled} -> {rule.enabled}')
                        ruleset.enabled = rule.enabled
                    if rule.source != ruleset.source:
                        self.logger.debug(f'Updating source {ruleset.source} -> {rule.source}')
                        ruleset.source = rule.source
                    if rule.source_port != ruleset.source_port:
                        self.logger.debug(f'Updating source_port {ruleset.source_port} -> {rule.source_port}')
                        ruleset.source_port = rule.source_port
                    if rule.direction != ruleset.direction:
                        self.logger.debug(f'Updating direction {ruleset.direction} -> {rule.direction}')
                        ruleset.direction = rule.direction
                    if rule.destination != ruleset.destination:
                        self.logger.debug(f'Updating destination {ruleset.destination} -> {rule.destination}')
                        ruleset.destination = rule.destination
                    if rule.destination_port != ruleset.destination_port:
                        self.logger.debug(f'Updating destination_port {ruleset.destination_port} -> '
                                          f'{rule.destination_port}')
                        ruleset.destination_port = rule.destination_port
                    if rule.options_blob() != ruleset.options_blob:
                        self.logger.debug(f'Updating destination_port {ruleset.options_blob} -> {rule.options_blob()}')
                        ruleset.options_blob = rule.options_blob()

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        """Dump the database to a suricata.rules file"""
        if not out_file_path:
            out_file_path = self.rule_file_path
        row_count = self.db_session.query(Ruleset.sid).count()
        self.logger.info(f'Dumping {row_count} rules to {out_file_path}.')
        with open(out_file_path, 'w') as rule_file_out:
            for row in self.db_session.query(Ruleset).order_by(Ruleset.lineno):
                rule = Rule.create_from_ruleset_entry(row)
                rule_file_out.write(str(rule) + '\n')