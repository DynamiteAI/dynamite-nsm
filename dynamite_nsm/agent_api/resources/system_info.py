from flask_restful import Resource

from dynamite_nsm import utilities


class CPUCoreCount(Resource):

    def get(self):
        return dict(cpu_core_count=utilities.get_cpu_core_count()), 200


class MemoryBytes(Resource):

    def get(self):
        return dict(memory_bytes=utilities.get_memory_available_bytes()), 200


class NetworkAddresses(Resource):

    def get(self):
        return dict(ip_addresses=utilities.get_network_addresses()), 200


class NetworkInterfaces(Resource):

    def get(self):
        return dict(interfaces=utilities.get_network_interface_names()), 200


class SystemInfo(Resource):

    def get(self):
        return dict(
            memory_bytes=utilities.get_memory_available_bytes(),
            cpu_core_count=utilities.get_cpu_core_count(),
            ip_addresses=utilities.get_network_addresses(),
            interfaces=utilities.get_network_interface_names()
        )
