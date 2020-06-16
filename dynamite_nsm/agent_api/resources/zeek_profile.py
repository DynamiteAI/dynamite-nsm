from flask_restplus import fields, Namespace, Resource

from dynamite_nsm.services.zeek import profile as zeek_profile


api = Namespace(
    name='Zeek Profile',
    description='Check if Zeek is installed.',
)

# RESPONSE MODELS ======================================================================================================

# GET /
model_response_zeek_installed = api.model('ZeekInstalled', model=dict(
    is_installed=fields.Boolean
))


@api.route('/', endpoint='zeek-installed')
class ZeekProfile(Resource):

    @api.doc('get_zeek_installed')
    @api.response(200, 'Checked Zeek installed.', model=model_response_zeek_installed)
    def get(self):
        zeek_prof = zeek_profile.ProcessProfiler()
        return dict(is_installed=zeek_prof.is_installed), 200
