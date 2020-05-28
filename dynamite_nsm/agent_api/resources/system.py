from flask_restplus import Namespace, Resource

from dynamite_nsm import utilities

api = Namespace(
    name='system',
    description='Get various information about the system the agent is installed on.',
)


@api.route('/')
class SystemInfo(Resource):

    def get(self):
        return dict(
            memory_bytes=utilities.get_memory_available_bytes(),
            cpu_core_count=utilities.get_cpu_core_count(),
            ip_addresses=utilities.get_network_addresses(),
            interfaces=utilities.get_network_interface_names()
        )


@api.route('/cpu/')
class CPUCoreCount(Resource):

    def get(self):
        return dict(cpu_core_count=utilities.get_cpu_core_count()), 200


@api.route('/memory/')
class MemoryBytes(Resource):

    def get(self):
        return dict(memory_bytes=utilities.get_memory_available_bytes()), 200


@api.route('/ips/')
class NetworkAddresses(Resource):

    def get(self):
        return dict(ip_addresses=utilities.get_network_addresses()), 200


@api.route('/interfaces/')
class NetworkInterfaces(Resource):

    def get(self):
        return dict(interfaces=utilities.get_network_interface_names()), 200
