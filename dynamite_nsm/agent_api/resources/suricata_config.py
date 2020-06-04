from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.agent_api import validators
from dynamite_nsm.services.suricata import config as suricata_config

api = Namespace(
    name='Suricata Configuration',
    description='Configure Suricata Instance Settings.',
)

env_vars = utilities.get_environment_file_dict()
SURICATA_CONFIG_DIRECTORY = env_vars.get('SURICATA_CONFIG')

model_suricata_address_groups = api.model('SuricataAddressGroupsResponse', model=dict(
    home_net=fields.String,
    external_net=fields.String,
    http_servers=fields.String,
    sql_servers=fields.String,
    dns_servers=fields.String,
    telnet_servers=fields.String,
    aim_servers=fields.String,
    domain_controllers=fields.String,
    modbus_server=fields.String,
    modbud_client=fields.String,
    enip_client=fields.String,
    enip_server=fields.String
))


@api.route('/address-groups', endpoint='suricata-address-groups-config')
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
            dc_servers=suricata_instance_config.dc_servers,
            modbus_server=suricata_instance_config.modbus_server,
            modbud_client=suricata_instance_config.modbus_client,
            enip_client=suricata_instance_config.enip_client,
            enip_server=suricata_instance_config.enip_server
        )


@api.route('/address-groups/<address_group>', endpoint='suricata-address-groups-manager')
class SuricataInterfacesConfig(Resource):

    def get(self):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        return suricata_instance_config.af_packet_interfaces, 200


@api.route('/address-groups/<address_group>', endpoint='suricata-address-group-manager')
class SuricataAddressGroupsManager(Resource):
    VALID_ADDRESS_GROUP_NAMES = ['home_net', 'external_net', 'http_servers', 'sql_servers', 'dns_servers',
                                 'telnet_servers', 'aim_servers', 'dc_servers', 'modbus_server', 'modbud_client',
                                 'enip_client', 'enip_server'
                                 ]

    def get(self, address_group):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        if not validators.validate_name(address_group):
            return dict(message='Invalid "address_group"; must be one of the following : {}'.format(
                self.VALID_ADDRESS_GROUP_NAMES)), 400
        return dict(address_group={'name': address_group, 'value': getattr(suricata_instance_config, address_group)})
