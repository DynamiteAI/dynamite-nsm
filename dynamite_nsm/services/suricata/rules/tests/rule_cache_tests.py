import os
import unittest
from dynamite_nsm.services.suricata.rules import objects
from dynamite_nsm.utilities import get_environment_file_dict, safely_remove_file


class TestSuricataRuleCache(unittest.TestCase):
    """
    Test the logic that handles Suricata rule caching
    """
    env_file = get_environment_file_dict()
    test_rules_directory = '/tmp/'

    suricata_config = env_file.get('SURICATA_CONFIG')
    suricata_rules = objects.RuleFile(f'{suricata_config}/data/rules/suricata.rules')
    delta_file = f'{suricata_config}/.deltas'

    def test_caches_are_equivalent(self):
        # Serialize the suricata.rules file located at /etc/dynamite/suricata/data/rules/suricata.rules
        # into a temporary sqlite3 cache; then dump the cache into a new file at /tmp/suricata-test.rules
        # and compare them against one another

        self.suricata_rules.commit(f'{self.test_rules_directory}/suricata-test.rules')
        temp_rule_file = objects.RuleFile(f'{self.test_rules_directory}/suricata-test.rules')
        equivalent = True
        for rule in self.suricata_rules:
            new_rule = temp_rule_file.get_rule(rule.sid)
            if not rule.compare(new_rule):
                equivalent = False
                break
        assert (equivalent is True)

    def test_add_rule(self):
        temp_rules_path = f'{self.test_rules_directory}/suricata-test.rules'
        os.rename(self.delta_file, f'{self.delta_file}.original')
        self.suricata_rules.commit(temp_rules_path)
        temp_rule_file = objects.RuleFile(temp_rules_path)
        temp_rule_file.build_cache()
        temp_rule_file.add_rule(
            objects.Rule(
                enabled=True,
                action='alert',
                proto='tcp',
                source='192.168.0.5/24',
                direction='->',
                destination='$EXTERNAL_NET',
                source_port='any',
                destination_port='[53,5353]',
                options=[('sid', 333333333)]
            )
        )
        temp_rule_file.merge()
        temp_rule_file.commit()
        os.rename(f'{self.delta_file}.original', self.delta_file)
        with open(temp_rules_path) as new_rules_in:
            new_rule_sid = objects.serialize_suricata_rule(new_rules_in.readline()).sid
        safely_remove_file(f'{self.test_rules_directory}/suricata-test.rules')
        assert (str(new_rule_sid) == str(333333333))

    @classmethod
    def tearDownClass(cls) -> None:
        if os.path.exists(f'{cls.delta_file}.original'):
            os.rename(f'{cls.delta_file}.original', cls.delta_file)
        if os.path.exists(f'{cls.suricata_config}/suricata-test.db'):
            safely_remove_file(f'{cls.suricata_config}/suricata-test.db')
