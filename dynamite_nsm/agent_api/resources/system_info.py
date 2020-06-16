from flask_restplus import fields, Namespace, Resource
from flask_security import roles_required

from dynamite_nsm import utilities

api = Namespace(
    name='System Information',
    description='Get various information about the system the agent is installed on.',
)

# GET /cpu
model_response_cpu_core_count = api.model('CPUCoreCountResponse', model={
    'cpu_core_count': fields.Integer
})


# GET /memory
model_response_memory_bytes = api.model('MemoryBytesResponse', model={
    'memory_bytes': fields.Integer
})


# GET /ips
model_response_network_addresses = api.model('NetworkAddressesResponse', model={
    'ip_addresses': fields.List(fields.String)
})


# GET /interfaces
model_response_network_interfaces = api.model('NetworkInterfacesResponse', model={
    'interfaces': fields.List(fields.String)
})


# GET /
model_response_system_info = api.model('SystemInfoResponse', model={
    'cpu_core_count': fields.Integer,
    'memory_bytes': fields.Integer,
    'ip_addresses': fields.List(fields.String),
    'interfaces': fields.List(fields.String)
})


@api.route('/')
@roles_required('admin')
class SystemInfo(Resource):
    @api.doc('get_system_info')
    @api.response(200, 'System Information', model=model_response_system_info)
    def get(self):
        return dict(
            memory_bytes=utilities.get_memory_available_bytes(),
            cpu_core_count=utilities.get_cpu_core_count(),
            ip_addresses=utilities.get_network_addresses(),
            interfaces=utilities.get_network_interface_names()
        )


@api.route('/cpu')
class CPUCoreCount(Resource):
    @api.doc('get_cpu_core_count')
    @api.response(200, 'CPU Core Count', model=model_response_cpu_core_count)
    def get(self):
        return dict(cpu_core_count=utilities.get_cpu_core_count()), 200


@api.route('/memory')
class MemoryBytes(Resource):
    @api.doc('get_memory_bytes')
    @api.response(200, 'Memory Bytes', model=model_response_memory_bytes)
    def get(self):
        return dict(memory_bytes=utilities.get_memory_available_bytes()), 200


@api.route('/ips')
class NetworkAddresses(Resource):
    @api.doc('get_network_addresses')
    @api.response(200, 'Network Addresses', model=model_response_network_addresses)
    def get(self):
        return dict(ip_addresses=utilities.get_network_addresses()), 200


@api.route('/interfaces')
class NetworkInterfaces(Resource):
    @api.doc('get_network_interfaces')
    @api.response(200, 'Network Interfaces', model=model_response_network_interfaces)
    def get(self):
        return dict(interfaces=utilities.get_network_interface_names()), 200
