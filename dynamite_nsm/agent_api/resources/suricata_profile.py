from flask_restplus import fields, Namespace, Resource

from dynamite_nsm.services.suricata import profile as suricata_profile


api = Namespace(
    name='Suricata Profile',
    description='Check if Suricata is installed.',
)

# RESPONSE MODELS ======================================================================================================

# GET /
model_response_suricata_installed = api.model('SuricataInstalled', model=dict(
    is_installed=fields.Boolean
))


@api.route('/', endpoint='suricata-installed')
class SuricataProfile(Resource):

    @api.doc('get_suricata_installed')
    @api.response(200, 'Checked Suricata installed.', model=model_response_suricata_installed)
    def get(self):
        suricata_prof = suricata_profile.ProcessProfiler()
        return dict(is_installed=suricata_prof.is_installed), 200
