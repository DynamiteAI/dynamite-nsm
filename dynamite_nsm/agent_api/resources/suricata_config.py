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
    modbus_client=fields.String,
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
            modbus_client=suricata_instance_config.modbus_client,
            enip_client=suricata_instance_config.enip_client,
            enip_server=suricata_instance_config.enip_server
        ), 200


@api.route('/port-groups', endpoint='port-groups-config')
class SuricataPortGroupsConfig(Resource):

    def get(self):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        return dict(
            http_ports=suricata_instance_config.http_ports,
            shellcode_ports=suricata_instance_config.shellcode_ports,
            oracle_ports=suricata_instance_config.oracle_ports,
            ssh_ports=suricata_instance_config.ssh_ports,
            dnp3_ports=suricata_instance_config.dnp3_ports,
            modbus_ports=suricata_instance_config.modbus_ports,
            file_data_ports=suricata_instance_config.file_data_ports,
            ftp_ports=suricata_instance_config.ftp_ports,
        ), 200


@api.route('/interfaces', endpoint='suricata-network-interfaces-config')
class SuricataInterfacesConfig(Resource):

    def get(self):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        return dict(interfaces=suricata_instance_config.list_af_packet_interfaces()), 200


@api.route('/interfaces/<interface>', endpoint='suricata-network-interface-manager')
class SuricataInterfaceManager(Resource):

    @staticmethod
    def _create_update(net_interface, verb='POST'):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        net_interfaces = utilities.get_network_interface_names()
        arg_parser = reqparse.RequestParser()
        if verb == 'POST':
            require_args = True
            success_code = 201
            interface = None
            threads = None
            cluster_id = None
            cluster_type = None
            bpf_filter = None
        else:
            interface_config = \
                [af_packet_interface
                 for af_packet_interface in suricata_instance_config.af_packet_interfaces if
                 af_packet_interface['interface'] == net_interface][0]
            require_args = False
            success_code = 200
            interface = interface_config['interface']
            if interface_config['threads'] != 'auto':
                threads = int(interface_config['threads'])
            else:
                threads = 'auto'
            cluster_id = int(interface_config['cluster-id'])
            cluster_type = interface_config['cluster-type']
            bpf_filter = interface_config.get('bpf-filter')

        arg_parser.add_argument(
            'interface', dest='interface',
            location='json', required=require_args, type=str,
            help='The network interface to monitor; valid interfaces: {}'.format(net_interfaces)
        )
        arg_parser.add_argument(
            'threads', dest='threads',
            location='json', required=require_args, type=str,
            help='The number of threads used to monitor your interface.'
        )
        arg_parser.add_argument(
            'cluster_id', dest='cluster_id',
            location='json', required=require_args, type=int,
            help='The AF_PACKET cluster id; AF_PACKET will load balance packets based on flow;'
                 ' valid choices are integers between 1 and 99.',
            choices=range(0, 100)
        )
        arg_parser.add_argument(
            'cluster_type', dest='cluster_type',
            location='json', required=require_args, type=str,
            help='A method by which packet-load-balancing is accomplished; valid choices are: {}'.format(
                ['cluster_flow', 'cluster_cpu', 'cluster_qm']),
            choices=['cluster_flow', 'cluster_cpu', 'cluster_qm']
        )
        arg_parser.add_argument(
            'bpf_filter', dest='bpf_filter',
            location='json', required=require_args, type=str,
            help='Berkeley Packet Filter expression used for filtering out undesired packets on this interface.'
        )

        args = arg_parser.parse_args()

        # Reassign interface operation
        if verb == 'PUT' and args.interface:
            if args.interface not in net_interfaces:
                return dict(message='Invalid interface; valid interfaces: {}'.format(net_interfaces)), 400
            interface = args.interface
        if args.interface:
            interface = args.interface
        if args.threads:
            threads = args.threads
        if args.cluster_id:
            cluster_id = args.cluster_id
        if args.cluster_type:
            cluster_type = args.cluster_type
        if args.bpf_filter:
            bpf_filter = args.bpf_filter
        if interface not in net_interfaces:
            return dict(message='Invalid interface; valid interfaces: {}'.format(net_interfaces)), 400

        try:
            suricata_instance_config.remove_afpacket_interface(net_interface)
            suricata_instance_config.add_afpacket_interface(interface=interface, threads=threads, cluster_id=cluster_id,
                                                            cluster_type=cluster_type, bpf_filter=bpf_filter)
            suricata_instance_config.write_config()
            try:
                interface_config = \
                    [af_packet_interface
                     for af_packet_interface in suricata_instance_config.af_packet_interfaces if
                     af_packet_interface['interface'] == net_interface][0]
            except IndexError:
                return dict(message='{} interface does not exists. Use POST to create.'.format(interface)), 400
            return dict(interface=interface_config), success_code
        except suricata_config.suricata_exceptions.WriteSuricataConfigError as e:
            return dict(message=str(e)), 500

    def get(self, interface):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        net_interfaces = utilities.get_network_interface_names()

        if interface not in net_interfaces:
            return dict(message='Invalid network interface.'), 400
        for net_interface in suricata_instance_config.af_packet_interfaces:
            if net_interface['interface'] == interface:
                return dict(interface=net_interface), 200
        return dict(message='Network interface not found.'), 404

    def put(self, interface):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        interface_names = \
            [af_packet_interface['interface'] for af_packet_interface in suricata_instance_config.af_packet_interfaces]
        if interface not in interface_names:
            return dict(message='{} interface does not exists. Use POST to create.'.format(interface)), 400
        return self._create_update(interface, verb='PUT')


@api.route('/address-groups/<address_group>', endpoint='suricata-address-group-manager')
class SuricataAddressGroupsManager(Resource):
    VALID_ADDRESS_GROUP_NAMES = ['home_net', 'external_net', 'http_servers', 'sql_servers', 'dns_servers',
                                 'telnet_servers', 'aim_servers', 'dc_servers', 'modbus_server', 'modbus_client',
                                 'enip_client', 'enip_server'
                                 ]

    def get(self, address_group):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        if not validators.validate_suricata_address_group_name(address_group):
            return dict(message='Invalid "address_group"; must be one of the following : {}'.format(
                self.VALID_ADDRESS_GROUP_NAMES)), 400
        return dict(
            address_group={'name': address_group, 'value': getattr(suricata_instance_config, address_group)}), 200

    def put(self, address_group):
        if not validators.validate_suricata_address_group_name(address_group):
            return dict(message='Invalid "address_group"; must be one of the following : {}'.format(
                self.VALID_ADDRESS_GROUP_NAMES)), 400
        var_sub = '$' + address_group.upper()
        corresponding_var_subs = [var_sub, '!' + var_sub]
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'group_expression', dest='group_expression',
            location='json', required=True, type=str,
            help='An expression representing an IP range or group, examples can be found here: '
                 'https://suricata.readthedocs.io/en/suricata-4.0.0-beta1/rules/intro.html#source-and-destination'
        )
        if not validators.validate_name(address_group):
            return dict(message='Invalid "address_group"; must be one of the following : {}'.format(
                self.VALID_ADDRESS_GROUP_NAMES)), 400
        args = arg_parser.parse_args()
        if args.group_expression.replace(' ', '') in corresponding_var_subs:
            return dict(
                message='{} cannot be {}, this would lead to circular references.'.format(args.group_expression,
                                                                                          corresponding_var_subs)
            ), 400
        if not validators.validate_suricata_address_group_values(args.group_expression):
            return dict(
                message='Invalid "group_expression"; '
                        'examples can be found here: '
                        'https://suricata.readthedocs.io/en/suricata-4.0.0-beta1/rules/intro.html'
                        '#source-and-destination'), 400
        setattr(suricata_instance_config, address_group, args.group_expression)
        suricata_instance_config.write_config()
        return dict(
            address_group={'name': address_group, 'value': getattr(suricata_instance_config, address_group)}), 200


@api.route('/port-groups/<port_group>', endpoint='suricata-port-group-manager')
class SuricataAddressGroupsManager(Resource):
    VALID_PORT_GROUP_NAMES = ['http_ports', 'shellcode_ports', 'oracle_ports', 'ssh_ports', 'dnp3_ports',
                              'modbus_ports', 'ftp_ports', 'file_data_ports']

    def get(self, port_group):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        if not validators.validate_suricata_port_group_name(port_group):
            return dict(message='Invalid "port_group"; must be one of the following : {}'.format(
                self.VALID_PORT_GROUP_NAMES)), 400
        return dict(
            port_group={'name': port_group, 'value': getattr(suricata_instance_config, port_group)}), 200

    def put(self, port_group):
        if not validators.validate_suricata_port_group_name(port_group):
            return dict(message='Invalid "port_group"; must be one of the following : {}'.format(
                self.VALID_PORT_GROUP_NAMES)), 400
        var_sub = '$' + port_group.upper()
        corresponding_var_subs = [var_sub, '!' + var_sub]
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'group_expression', dest='group_expression',
            location='json', required=True, type=str,
            help='An expression representing an group of ports, examples can be found here: '
                 'https://suricata.readthedocs.io/en/suricata-4.0.0-beta1/rules/intro.html#'
                 'ports-source-and-destination-port'
        )
        if not validators.validate_name(port_group):
            return dict(message='Invalid "port_group"; must be one of the following : {}'.format(
                self.VALID_ADDRESS_GROUP_NAMES)), 400
        args = arg_parser.parse_args()
        if args.group_expression.replace(' ', '') in corresponding_var_subs:
            return dict(
                message='{} cannot be {}, this would lead to circular references.'.format(args.group_expression,
                                                                                          corresponding_var_subs)
            ), 400
        if not validators.validate_suricata_port_group_values(args.group_expression):
            return dict(
                message='Invalid "group_expression"; '
                        'examples can be found here: https://suricata.readthedocs.io/en/suricata-4.0.0-beta1/rules/'
                        'intro.html#ports-source-and-destination-port'), 400
        setattr(suricata_instance_config, port_group, args.group_expression)
        suricata_instance_config.write_config()
        return dict(
            port_group={'name': port_group, 'value': getattr(suricata_instance_config, port_group)}), 200
