from zlib import adler32
from flask_security import roles_accepted
from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.suricata import config as suricata_config

api = Namespace(
    name='Suricata Rules',
    description='Enable/Disable Suricata Rules.',
)

# BASE MODELS ==========================================================================================================

model_suricata_rule_no_status = api.model(
    'SuricataRuleNoStatus', model=dict(
        id=fields.Integer,
        name=fields.String,
    )
)

model_suricata_rule_status = api.model(
    'SuricataRuleWithStatus', model=dict(
        id=fields.Integer,
        name=fields.String,
        status=fields.String
    )
)

model_suricata_rules = api.model(
    'SuricataRules', model=dict(
        enabled=fields.List(fields.Nested(model_suricata_rule_no_status)),
        disabled=fields.List(fields.Nested(model_suricata_rule_no_status))
    )
)

# REQUEST MODELS =======================================================================================================

model_request_suricata_update_rule = api.model('SuricataRuleRequest', model=dict(
    status=fields.String(pattern='enabled|disabled')
))

# RESPONSE MODELS ======================================================================================================

# GET /
model_response_suricata_rules = api.model('SuricataRulesResponse', model=dict(
    rules=fields.Nested(model_suricata_rules)
))

# GET, PUT /<rule_id>
model_response_suricata_rule = api.model(
    'SuricataRuleResponse', model=dict(
        rule=fields.Nested(model_suricata_rule_status)
    )
)

# multiple endpoints
model_response_error = api.model('ErrorResponse', model={
    'message': fields.String
})

# multiple endpoints
model_response_generic_success = api.model('GenericSuccessResponse', model={
    'message': fields.String
})


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

    @api.doc('list_suricata_rules')
    @api.response(200, 'Listed Suricata rules.', model=model_response_suricata_rules)
    @roles_accepted('admin', 'superuser', 'analyst')
    def get(self):
        rules_config = suricata_config.ConfigManager(SURICATA_CONFIG_DIRECTORY)
        rules_and_ids = self.hash_and_id_rules(rules_config.list_enabled_rules(), rules_config.list_disabled_rules())
        return dict(rules=rules_and_ids), 200


@api.route('/<rule_id>', endpoint='rule-manager')
class SuricataRuleManager(Resource):

    @api.doc('get_suricata_rule')
    @api.param('rule_id', description='A numeric identifier representing a Suricata rule.')
    @api.response(200, 'Fetched Suricata rule.', model=model_response_suricata_rule)
    @api.response(404, 'Could not find Suricata rule.', model=model_response_error)
    @roles_accepted('admin', 'superuser', 'analyst')
    def get(self, rule_id):
        rules_config = suricata_config.ConfigManager(SURICATA_CONFIG_DIRECTORY)
        rules_and_ids = SuricataRuleConfig.hash_and_id_rules(rules_config.list_enabled_rules(),
                                                             rules_config.list_disabled_rules())
        enabled_rules = [str(rule['id']) for rule in rules_and_ids['enabled']]
        disabled_rules = [str(rule['id']) for rule in rules_and_ids['disabled']]

        if rule_id in enabled_rules:
            idx = enabled_rules.index(rule_id)
            rules_and_ids['enabled'][idx].update({'status': 'enabled'})
            return dict(rule=rules_and_ids['enabled'][idx]), 200
        elif rule_id in disabled_rules:
            idx = disabled_rules.index(rule_id)
            rules_and_ids['disabled'][idx].update({'status': 'disabled'})
            return dict(rule=rules_and_ids['disabled'][idx]), 200
        else:
            return dict(message='Could not find rule {}'.format(rule_id)), 404

    @api.doc('update_suricata_rule')
    @api.param('script_id', description='A numeric identifier representing a Suricata rule.')
    @api.expect(model_request_suricata_update_rule)
    @api.response(200, 'Updated Suricata Script.', model=model_response_generic_success)
    @api.response(404, 'Could not find Suricata rule.', model=model_response_error)
    @roles_accepted('admin', 'superuser')
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
        enabled_rules = [str(rule['id']) for rule in rules_and_ids['enabled']]
        disabled_rules = [str(rule['id']) for rule in rules_and_ids['disabled']]
        if rule_id in enabled_rules:
            idx = enabled_rules.index(rule_id)
            rule_name = rules_and_ids['enabled'][idx]['name']
        elif rule_id in disabled_rules:
            idx = disabled_rules.index(rule_id)
            rule_name = rules_and_ids['disabled'][idx]['name']
        else:
            return dict(message='Could not find rule {}'.format(rule_id)), 404

        if args.status == 'enabled' or args.status == 'enable':
            try:
                rules_config.enable_rule(rule_name)
            except suricata_config.suricata_exceptions.SuricataRuleNotFoundError:
                pass
            action = 'enabled'
        else:
            try:
                rules_config.disable_rule(rule_name)
            except suricata_config.suricata_exceptions.SuricataRuleNotFoundError:
                pass
            action = 'disabled'
        try:
            rules_config.write_config()
        except suricata_config.suricata_exceptions.WriteSuricataConfigError as e:
            return dict(message=str(e)), 500
        return dict(message='Rule {} ({}) {}.'.format(rule_id, rule_name, action)), 200
