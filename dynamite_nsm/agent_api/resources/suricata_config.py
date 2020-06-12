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

model_suricata_address_groups = api.model('SuricataAddressGroups', model=dict(
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

model_suricata_port_groups = api.model('SuricataPortGroups', model=dict(
    http_ports=fields.String,
    shellcode_ports=fields.String,
    oracle_ports=fields.String,
    ssh_ports=fields.String,
    dnp3_ports=fields.String,
    modbus_ports=fields.String,
    file_data_ports=fields.String,
    ftp_ports=fields.String,
))

# BASE MODELS ==========================================================================================================

model_suricata_group = api.model('SuricataGroup', model=dict(
    name=fields.String,
    value=fields.String
))

model_suricata_interfaces = api.model('SuricataInterfaces', model=dict(
    values=fields.List(fields.String)
))

model_suricata_interface = api.model('SuricataInterface', model={
    "bpf-filter": fields.String,
    "cluster-id": fields.Integer,
    "cluster-type": fields.String,
    "interface": fields.String,
    "threads": fields.String
})

# REQUEST MODELS =======================================================================================================

model_request_create_suricata_interface = api.model('SuricataInterfaceRequest', model={
    "bpf_filter": fields.String,
    "cluster_id": fields.Integer,
    "cluster_type": fields.String,
    "threads": fields.String
}),

model_request_update_suricata_interface = api.model('SuricataInterfaceRequest', model={
    "interface": fields.String(required=False),
    "bpf_filter": fields.String(required=False),
    "cluster_id": fields.Integer(required=False),
    "cluster_type": fields.String(required=False),
    "threads": fields.String(required=False),
})

# RESPONSE MODELS ======================================================================================================

# multiple endpoints
model_response_error = api.model('ErrorResponse', model={
    'message': fields.String
})

# multiple endpoints
model_response_generic_success = api.model('GenericSuccessResponse', model={
    'message': fields.String
})

# GET /address-groups
model_response_suricata_address_groups = api.model('SuricataGetAddressGroupsResponse', model=dict(
    address_groups=fields.Nested(model_suricata_address_groups)
))

# GET /port-groups
model_response_suricata_port_groups = api.model('SuricataGetPortGroupsResponse', model=dict(
    port_groups=fields.Nested(model_suricata_port_groups)
))

# GET /interfaces
model_response_suricata_interfaces = api.model('SuricataGetInterfacesResponse', model=dict(
    interfaces=fields.Nested(model_suricata_interfaces)
))

# GET, POST, PUT /interfaces/<interface>
model_response_suricata_interface = api.model('SuricataInterfaceResponse', model=dict(
    interface=fields.Nested(model_suricata_interface)
))

# GET, PUT /address-groups/<address_group>
model_response_suricata_address_group = api.model('SuricataModelAddressGroupResponse', model=dict(
    address_group=fields.Nested(model_suricata_group)
))

# GET, PUT /port-groups/<port_group>
model_response_suricata_port_group = api.model('SuricataModelPortGroupResponse', model=dict(
    port_group=fields.Nested(model_suricata_group)
))


@api.route('/address-groups', endpoint='suricata-address-groups-config')
class SuricataAddressGroupsConfig(Resource):

    @api.doc('list_suricata_address_groups')
    @api.response(200, 'Listed address groups.', model=model_response_suricata_address_groups)
    def get(self):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        return dict(
            address_groups=dict(
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
            )
        ), 200


@api.route('/port-groups', endpoint='port-groups-config')
class SuricataPortGroupsConfig(Resource):

    @api.doc('list_suricata_port_groups')
    @api.response(200, 'Listed port groups.', model=model_response_suricata_port_groups)
    def get(self):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        return dict(
            port_groups=dict(
                http_ports=suricata_instance_config.http_ports,
                shellcode_ports=suricata_instance_config.shellcode_ports,
                oracle_ports=suricata_instance_config.oracle_ports,
                ssh_ports=suricata_instance_config.ssh_ports,
                dnp3_ports=suricata_instance_config.dnp3_ports,
                modbus_ports=suricata_instance_config.modbus_ports,
                file_data_ports=suricata_instance_config.file_data_ports,
                ftp_ports=suricata_instance_config.ftp_ports
            )
        ), 200


@api.route('/interfaces', endpoint='suricata-network-interfaces-config')
class SuricataInterfacesConfig(Resource):

    @api.doc('list_suricata_interfaces')
    @api.response(200, 'Listed network interfaces', model=model_response_suricata_interfaces)
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
            interface = net_interface
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
            threads = interface_config['threads']
            cluster_id = int(interface_config['cluster-id'])
            cluster_type = interface_config['cluster-type']
            bpf_filter = interface_config.get('bpf-filter')

        arg_parser.add_argument(
            'interface', dest='interface',
            location='json', required=False, type=str,
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
            if args.interface in suricata_instance_config.list_af_packet_interfaces():
                return dict(message='An interface configuration for {} already exits. Please choose a different name, '
                                    'or delete {} interface config first.'.format(args.interface, args.interface)), 400
            if args.interface not in net_interfaces:
                return dict(message='Invalid interface; valid interfaces: {}'.format(net_interfaces)), 400
            interface = args.interface
        if args.interface:
            interface = args.interface
        if args.threads:
            if not (validators.validate_integer(args.threads) or args.threads == 'auto'):
                return dict(message="Invalid threads option; valid options are any integer or 'auto' keyword."), 400
            threads = args.threads
        if args.cluster_id:
            cluster_id = args.cluster_id
        if args.cluster_type:
            cluster_type = args.cluster_type
        if args.bpf_filter:
            bpf_filter = args.bpf_filter
            success, msg = validators.validate_bpf_filter(bpf_filter, include_message=True)
            if not success:
                return dict(message='Invalid BPF Filter: {}'.format(msg)), 400
        if interface not in net_interfaces:
            return dict(message='Invalid interface; valid interfaces: {}'.format(net_interfaces)), 400

        try:
            if verb == 'PUT':
                suricata_instance_config.remove_afpacket_interface(net_interface)
            suricata_instance_config.add_afpacket_interface(interface=interface, threads=threads, cluster_id=cluster_id,
                                                            cluster_type=cluster_type, bpf_filter=bpf_filter)
            suricata_instance_config.write_config()
            try:
                interface_config = \
                    [af_packet_interface
                     for af_packet_interface in suricata_instance_config.af_packet_interfaces if
                     af_packet_interface['interface'] == interface][0]
            except IndexError:
                return dict(message='{} interface does not exists. Use POST to create.'.format(interface)), 400
            return dict(interface=interface_config), success_code
        except suricata_config.suricata_exceptions.WriteSuricataConfigError as e:
            return dict(message=str(e)), 500

    @api.doc('delete_suricata_network_interface')
    @api.param('interface', description='A configured network interface.')
    @api.response(200, 'Deleted network interface.', model=model_response_generic_success)
    @api.response(400, 'Invalid network interface (not configured in Suricata) or bad value(s).',
                  model=model_response_error)
    @api.response(404, 'Could not find network interface.', model=model_response_error)
    def delete(self, interface):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        net_interfaces = utilities.get_network_interface_names()
        if interface not in net_interfaces:
            return dict(message='Invalid network interface.'), 400
        elif interface not in suricata_instance_config.list_af_packet_interfaces():
            return dict(message='Network interface not found.'), 404
        suricata_instance_config.remove_afpacket_interface(interface)
        suricata_instance_config.write_config()
        return dict(message='Deleted network interface {}.'.format(interface)), 200

    @api.doc('get_suricata_network_interface')
    @api.param('interface', description='A configured network interface.')
    @api.response(200, 'Fetched network interface.', model=model_response_suricata_interface)
    @api.response(400, 'Invalid network interface (not configured in Suricata).', model=model_response_error)
    @api.response(404, 'Could not find network interface.', model=model_response_error)
    def get(self, interface):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        net_interfaces = utilities.get_network_interface_names()

        if interface not in net_interfaces:
            return dict(message='Invalid network interface.'), 400
        for net_interface in suricata_instance_config.af_packet_interfaces:
            if net_interface['interface'] == interface:
                return dict(interface=net_interface), 200
        return dict(message='Network interface not found.'), 404

    @api.doc('create_suricata_network_interface')
    @api.param('interface', description='A valid network interface.')
    @api.expect(model_request_create_suricata_interface)
    @api.response(201, 'Created network interface.', model=model_response_suricata_interface)
    @api.response(400, 'Invalid network interface (already exists) or bad value(s).', model=model_response_error)
    def post(self, interface):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        interface_names = \
            [af_packet_interface['interface'] for af_packet_interface in suricata_instance_config.af_packet_interfaces]
        if interface in interface_names:
            return dict(message='{} interface already exists. Use PUT to update.'.format(interface)), 400
        return self._create_update(interface, verb='POST')

    @api.doc('update_suricata_network_interface')
    @api.param('interface', description='A valid network interface.')
    @api.expect(model_request_update_suricata_interface)
    @api.response(201, 'Updated network interface.', model=model_response_suricata_interface)
    @api.response(400, 'Invalid network interface (does not exists) or bad value(s).', model=model_response_error)
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

    @api.doc('get_address_group')
    @api.param('address_group', 'The name of the address group to get details about.')
    @api.response(200, 'Fetched Suricata address group.', model=model_response_suricata_address_group)
    @api.response(400, 'Invalid address group.', model=model_response_error)
    def get(self, address_group):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        if not validators.validate_suricata_address_group_name(address_group):
            return dict(message='Invalid "address_group"; must be one of the following : {}'.format(
                self.VALID_ADDRESS_GROUP_NAMES)), 400
        return dict(
            address_group={'name': address_group, 'value': getattr(suricata_instance_config, address_group)}), 200

    @api.doc('update_address_group')
    @api.param('address_group', 'The name of the address group to update.')
    @api.response(200, 'Updated Suricata address group.', model=model_response_suricata_address_group)
    @api.response(400, 'Invalid address group; invalid group expression.', model=model_response_error)
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
class SuricataPortGroupsManager(Resource):
    VALID_PORT_GROUP_NAMES = ['http_ports', 'shellcode_ports', 'oracle_ports', 'ssh_ports', 'dnp3_ports',
                              'modbus_ports', 'ftp_ports', 'file_data_ports']

    @api.doc('get_port_group')
    @api.param('port_group', 'The name of the port group to get details about.')
    @api.response(200, 'Fetched Suricata port group.', model=model_response_suricata_port_group)
    @api.response(400, 'Invalid port group.', model=model_response_error)
    def get(self, port_group):
        suricata_instance_config = suricata_config.ConfigManager(configuration_directory=SURICATA_CONFIG_DIRECTORY)
        if not validators.validate_suricata_port_group_name(port_group):
            return dict(message='Invalid "port_group"; must be one of the following : {}'.format(
                self.VALID_PORT_GROUP_NAMES)), 400
        return dict(
            port_group={'name': port_group, 'value': getattr(suricata_instance_config, port_group)}), 200

    @api.doc('update_port_group')
    @api.param('port_group', 'The name of the port group to update.')
    @api.response(200, 'Updated Suricata port group.', model=model_response_suricata_port_group)
    @api.response(400, 'Invalid port group; invalid group expression.', model=model_response_error)
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
