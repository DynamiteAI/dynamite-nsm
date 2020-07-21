from flask_security import roles_accepted
from flask_restplus import fields, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.filebeat import profile as filebeat_profile


api = Namespace(
    name='FileBeat Profile',
    description='Check if FileBeat is installed.',
)

# RESPONSE MODELS ======================================================================================================

# GET /
model_response_filebeat_installed = api.model('FileBeat', model=dict(
    is_installed=fields.Boolean,
    filebeat_home=fields.String
))


@api.route('/', endpoint='filebeat-installed')
@api.header('Content-Type', 'application/json', required=True)
class FilebeatProfile(Resource):

    @api.doc('get_filebeat_installed', security='apikey')
    @api.response(200, 'Checked FileBeat installed.', model=model_response_filebeat_installed)
    @roles_accepted('admin', 'superuser', 'analyst')
    def get(self):
        env_vars = utilities.get_environment_file_dict()
        filebeat_prof = filebeat_profile.ProcessProfiler()
        return dict(
            is_installed=filebeat_prof.is_installed,
            filebeat_home=env_vars.get('FILEBEAT_HOME'),
        ), 200
