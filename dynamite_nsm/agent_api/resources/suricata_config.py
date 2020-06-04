from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.suricata import config as suricata_config

api = Namespace(
    name='Suricata Configuration',
    description='Configure Suricata Instance Settings.',
)

env_vars = utilities.get_environment_file_dict()
SURICATA_CONFIG_DIRECTORY = env_vars.get('SURICATA_CONFIG')


@api.route('/', endpoint='suricata-interfaces')
class SuricataInterfaces(Resource):

    def get(self):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        return suricata_instance_config.af_packet_interfaces, 200
