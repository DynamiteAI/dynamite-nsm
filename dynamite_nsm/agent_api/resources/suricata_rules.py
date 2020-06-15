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


@api.route('/<rule_id>', endpoint='rule-manager')
class SuricataRuleManager(Resource):

    def get(self, rule_id):
        rules_config = suricata_config.ConfigManager(SURICATA_CONFIG_DIRECTORY)
        rules_and_ids = SuricataRuleConfig.hash_and_id_rules(rules_config.list_enabled_rules(),
                                                             rules_config.list_disabled_rules())
        enabled_rules = [str(script['id']) for script in rules_and_ids['enabled']]
        disabled_rules = [str(script['id']) for script in rules_and_ids['disabled']]

        if rule_id in enabled_rules:
            idx = enabled_rules.index(rule_id)
            rules_and_ids['enabled'][idx].update({'status': 'enabled'})
            return dict(rule=rules_and_ids['enabled'][idx]), 200
        elif rule_id in disabled_rules:
            idx = disabled_rules.index(rule_id)
            rules_and_ids['disabled'][idx].update({'status': 'disabled'})
            return dict(script=rules_and_ids['disabled'][idx]), 200
        else:
            return dict(message='Could not find rule {}'.format(rule_id)), 404

    def put(self, rule_id):
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'status', dest='status',
            location='json', required=True, type=str, choices=['enabled', 'disabled', 'enable', 'disable'],
            help='Enable/Disable a rule.'
        )
        args = arg_parser.parse_args()

        rules_config = suricata_config.ConfigManager(SURICATA_CONFIG_DIRECTORY)
        rules_and_ids = SuricataRuleConfig.hash_and_id_rules(rules_config.list_enabled_rules(),
                                                             rules_config.list_disabled_rules())
        enabled_rules = [str(script['id']) for script in rules_and_ids['enabled']]
        disabled_rules = [str(script['id']) for script in rules_and_ids['disabled']]
        if rule_id in enabled_rules:
            idx = enabled_rules.index(rule_id)
            rule_name = rules_and_ids['enabled'][idx]['name']
        elif rule_id in disabled_rules:
            idx = disabled_rules.index(rule_id)
            rule_name = rules_and_ids['disabled'][idx]['name']
        else:
            return dict(message='Could not find rule {}'.format(rule_id)), 404

        if args.status == 'enabled' or args.status == 'enable':
            rules_config.enable_rule(rule_name)
            action = 'enabled'
        else:
            rules_config.disable_rule(rule_name)
            action = 'disabled'
        try:
            rules_config.write_config()
        except suricata_config.suricata_exceptions.WriteSuricataConfigError as e:
            return dict(message=str(e)), 500
        return dict(message='Rule {} ({}) {}.'.format(rule_id, rule_name, action)), 200
