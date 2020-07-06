from os import path
from flask_security import roles_accepted
from flask_restplus import fields, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.suricata import profile as suricata_profile


api = Namespace(
    name='Suricata Profile',
    description='Check if Suricata is installed.',
)

# RESPONSE MODELS ======================================================================================================

# GET /
model_response_suricata_installed = api.model('SuricataInstalled', model=dict(
    is_installed=fields.Boolean,
    suricata_home=fields.String,
    suricata_config=fields.String,
    suricata_rules=fields.String
))


@api.route('/', endpoint='suricata-installed')
class SuricataProfile(Resource):

    @api.doc('get_suricata_installed')
    @api.response(200, 'Checked Suricata installed.', model=model_response_suricata_installed)
    @roles_accepted('admin', 'superuser', 'analyst')
    def get(self):
        env_vars = utilities.get_environment_file_dict()
        suricata_prof = suricata_profile.ProcessProfiler()
        if env_vars.get('SURICATA_CONFIG'):
            suricata_rules = path.join(env_vars.get('SURICATA_CONFIG'), 'rules')
        else:
            suricata_rules = None
        return dict(
            is_installed=suricata_prof.is_installed,
            suricata_home=env_vars.get('SURICATA_HOME'),
            suricata_config=env_vars.get('SURICATA_CONFIG'),
            suricata_rules=suricata_rules
        ), 200
