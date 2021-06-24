import json
from typing import Optional, List

from dynamite_nsm.services.base.config_objects.generic import Analyzer, Analyzers


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


def list_available_rule_names() -> List[str]:
    """List the names of all available Suricata rules.
    Returns:
        A list of Suricata rule names that can be enabled
    """
    return available_rules_names


class Rule(Analyzer):

    def __init__(self, name: str, enabled: Optional[bool] = False):
        """
        Represents a Suricata ruleset that can be enabled or disabled.
        Args:
            name: The name of the ruleset
            enabled: Whether or not the ruleset is enabled
        """
        self.value = None
        super().__init__(name, enabled)


class Rules(Analyzers):

    def __init__(self, rules: Optional[List[Rule]] = None):
        """A collection of Suricata rulesets
        Args:
            rules: A list of Rule objects
        """
        super().__init__(rules)
        self.rules = self.analyzers

    def __str__(self):
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                rules=[f'{rule.name} (enabled: {rule.enabled})' for rule in self.rules]
            )
        )
