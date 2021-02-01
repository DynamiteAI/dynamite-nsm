import json
from typing import Optional, List

available_rules_names = [
    'botcc.rules', 'botcc.portgrouped.rules', 'ciarmy.rules',
    'compromised.rules', 'drop.rules', 'dshield.rules',
    'emerging-attack_response.rules', 'emerging-chat.rules',
    'emerging-current_events.rules', 'emerging-dns.rules',
    'emerging-dos.rules', 'emerging-exploit.rules',
    'emerging-ftp.rules', 'emerging-imap.rules',
    'emerging-malware.rules', 'emerging-misc.rules',
    'emerging-mobile_malware.rules', 'emerging-netbios.rules',
    'emerging-p2p.rules', 'emerging-policy.rules',
    'emerging-pop3.rules', 'emerging-rpc.rules',
    'emerging-smtp.rules', 'emerging-snmp.rules',
    'emerging-sql.rules', 'emerging-telnet.rules',
    'emerging-tftp.rules', 'emerging-trojan.rules',
    'emerging-user_agents.rules', 'emerging-voip.rules',
    'emerging-web_client.rules', 'emerging-web_server.rules',
    'emerging-worm.rules', 'tor.rules',
    'http-events.rules', 'smtp-events.rules',
    'dns-events.rules', 'tls-events.rules'
]


def list_available_rule_names():
    return available_rules_names


class Rule:

    def __init__(self, name: str, enabled: Optional[bool] = False):
        self.name = name
        self.enabled = enabled

    def __str__(self):
        return json.dumps(dict(
            obj_name=str(self.__class__),
            name=self.name,
            enabled=self.enabled
        ))


class Rules:

    def __init__(self, rules: Optional[List[Rule]] = None):
        self.rules = rules
        if rules is None:
            self.rules = []
        self._idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._idx >= len(self.rules):
            raise StopIteration
        current_rule = self.rules[self._idx]
        self._idx += 1
        return current_rule

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    def get_by_name(self, name: str) -> Optional[Rule]:
        for rule in self.rules:
            if rule.name == name:
                return rule
        return None

    def get_disabled(self) -> List[Rule]:
        return [rule for rule in self.rules if not rule.enabled]

    def get_enabled(self) -> List[Rule]:
        return [rule for rule in self.rules if rule.enabled]

    def get_raw(self) -> List[str]:
        return [rule.name for rule in self.rules if rule.enabled]
