from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.suricata import config as suricata_config

api = Namespace(
    name='Suricata Configuration',
    description='Configure Suricata Instance Settings.',
)

env_vars = utilities.get_environment_file_dict()
SURICATA_CONFIG_DIRECTORY = env_vars.get('SURICATA_CONFIG')


@api.route('/address-groups', endpoint='suricata-config')
class SuricataAddressGroupsConfig(Resource):

    def get(self):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        return dict(
            home_net=suricata_instance_config.home_net,
            external_net=suricata_instance_config.external_net,
            http_servers=suricata_instance_config.http_servers,
            sql_servers=suricata_instance_config.sql_servers,
            dns_servers=suricata_instance_config.dns_servers,
            telnet_servers=suricata_instance_config.telnet_servers,
            aim_servers=suricata_instance_config.aim_servers,
            domain_controllers=suricata_instance_config.dc_servers,
            modbus_server=suricata_instance_config.modbus_server,
            modbud_client=suricata_instance_config.modbus_client,
            enip_client=suricata_instance_config.enip_client,
            enip_server=suricata_instance_config.enip_server
        )


@api.route('/interfaces', endpoint='suricata-interfaces')
class SuricataInterfacesConfig(Resource):

    def get(self):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        return dict(interfaces=suricata_instance_config.af_packet_interfaces), 200

