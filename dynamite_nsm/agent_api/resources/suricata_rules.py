from zlib import adler32
from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.suricata import config as suricata_config

api = Namespace(
    name='Suricata Rules',
    description='Enable/Disable Suricata Rules.',
)

env_vars = utilities.get_environment_file_dict()
SURICATA_CONFIG_DIRECTORY = env_vars.get('SURICATA_CONFIG')


@api.route('/', endpoint='rules-config')
class SuricataRuleConfig(Resource):

    @staticmethod
    def hash_and_id_rules(enabled_rules, disabled_rules):
        rule_count = len(enabled_rules) + len(disabled_rules)
        return dict(
            enabled=sorted([{"id": adler32(str(name).encode("utf-8")) % (rule_count ** 3), "name": name} for name in
                            enabled_rules], key=lambda i: i['id']),
            disabled=sorted([{"id": adler32(str(name).encode("utf-8")) % (rule_count ** 3), "name": name} for name in
                             disabled_rules], key=lambda i: i['id'])
        )

    def get(self):
        rules_config = suricata_config.ConfigManager(SURICATA_CONFIG_DIRECTORY)
        rules_and_ids = self.hash_and_id_rules(rules_config.list_enabled_rules(), rules_config.list_disabled_rules())
        return dict(rules=rules_and_ids), 200

