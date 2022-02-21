from __future__ import annotations
import re
from typing import List


from dynamite_nsm.services.suricata.rules import validators
from dynamite_nsm.services.suricata.rules.database import Ruleset
from dynamite_nsm.services.suricata.rules.database import db_session, init_ruleset_db
from dynamite_nsm.services.base.config import GenericConfigManager


class MissingSid(Exception):
    def __init__(self):
        msg = f"This rule is missing an 'sid'."
        super(MissingSid, self).__init__(msg)


class InvalidRule(Warning):
    def __init__(self, sid, msg):
        msg = f"SID: {sid} is invalid: {msg}."
        super(InvalidRule, self).__init__(msg)


def serialize_suricata_rule(rule: str) -> Rule:
    """Convert a plaintext Suricata rule into a Rule object
    Args:
        rule: A plaintext Suricata rule

    Returns:
        A Suricata Rule object

    """
    enabled = False
    if rule.startswith('#'):
        enabled = True
        rule = rule[1:].strip()
    rule_tokenized_by_open_paren = rule.split('(')
    action_header = re.sub('\s+', ' ', rule_tokenized_by_open_paren[0])
    rule_options = ''.join(rule_tokenized_by_open_paren[1:]).strip(')')[0:-2]
    action = action_header.split(' ')[0].strip()
    header = action_header.replace(action, '').strip()
    header_proto = header.split(' ')[0].strip()
    header_source = header.split(' ')[1].strip()
    header_source_port = header.split(' ')[2].strip()
    header_direction = header.split(' ')[3].strip().strip(')')
    header_destination = header.split(' ')[4].strip()
    header_destination_port = header.split(' ')[5].strip()
    options = []
    for opt in rule_options.split(';'):
        opt = opt.strip()
        if not opt:
            continue
        opts = opt.split(':')
        if len(opts) == 2:
            k, v = opts
            options.append((k, v))
        elif len(opts) == 1:
            options.append(opts[0])
    return Rule(enabled, action, header_proto, header_source, header_source_port, header_direction, header_destination,
                header_destination_port, options)


class Rule:

    def __init__(self, enabled: bool, action: str, proto: str, source: str, source_port: str, direction: str,
                 destination: str, destination_port: str, options: List):
        self.sid = None
        self.enabled = enabled
        self.action = action
        self.proto = proto
        self.source = source
        self.source_port = source_port
        self.direction = direction
        self.destination = destination
        self.destination_port = destination_port
        self.options = options
        self.parse_sid()

    def parse_sid(self):
        """Parse out the required SID field from given options
        Returns:
            The SID of the rule.
        """
        key_val_opts = dict([opt for opt in self.options if isinstance(opt, tuple)])
        sid = key_val_opts.get('sid')
        if not sid:
            raise MissingSid()
        self.sid = sid

    def header(self) -> str:
        """Retrieve the rule header
        Returns:
            The rule header (E.G tcp 192.168.0.5 any -> 192.168.0.13 3289)
        """
        return f'{self.action} {self.proto} {self.source} {self.source_port} {self.direction} {self.destination_port}'

    def options_blob(self) -> str:
        """Retrieve the rule options as a string
        Returns:
            A String representation of the rule options
        """
        options = []
        for opt in self.options:
            if isinstance(opt, tuple):
                k, v = opt
                options.append(f'{k}:{v}')
            elif isinstance(opt, str):
                options.append(opt)
        return ';'.join(options)

    def __str__(self):
        enabled = '#' if self.enabled else ''
        return f'{enabled}{self.action} {self.proto} {self.source} {self.source_port} {self.direction} ' \
               f'{self.destination_port} ({self.options_blob()})'


class RuleFile(GenericConfigManager):

    def __init__(self, rule_file_path: str):
        super().__init__({}, 'suricata.rules.manager')
        self.rule_file_path = rule_file_path

    def build_cache(self):
        init_ruleset_db()
        with open(self.rule_file_path, 'r') as rule_file_in:
            for i, line in enumerate(rule_file_in.readlines()):
                r = serialize_suricata_rule(line)
                if not validators.validate_suricata_address_group_values(r.source):
                    self.logger.warning(f'{r.sid} source ({r.source}) is not valid.')
                if not validators.validate_suricata_port_group_values(r.source_port):
                    self.logger.warning(f'{r.sid} source_port ({r.source_port}) is not valid.')
                elif not validators.validate_suricata_address_group_values(r.destination):
                    self.logger.warning(f'{r.sid} destination ({r.destination}) is not valid.')
                if not validators.validate_suricata_port_group_values(r.destination_port):
                    self.logger.warning(f'{r.sid} destination_port ({r.destination_port}) is not valid.')
                rs = Ruleset(
                    sid=r.sid,
                    lineno=i + 1,
                    enabled=r.enabled,
                    proto=r.proto,
                    source=r.source,
                    source_port=r.source_port,
                    direction=r.direction,
                    destination=r.destination,
                    destination_port=r.destination_port,
                    options_blob=r.options_blob()
                )
                db_session.add(rs)
            db_session.commit()


if __name__ == '__main__':

    RuleFile('/etc/dynamite/suricata/data/rules/suricata.rules').build_cache()
