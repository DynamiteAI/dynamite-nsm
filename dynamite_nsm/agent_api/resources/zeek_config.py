from flask_restful import fields, reqparse, marshal_with, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.zeek import config as zeek_config

env_vars = utilities.get_environment_file_dict()
ZEEK_INSTALL_DIRECTORY = env_vars.get('ZEEK_HOME')


class ZeekNodeComponentsList(Resource):

    def __init__(self):
        self.node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)

    def get(self):
        manager = self.node_config.get_manager()
        loggers = self.node_config.list_loggers()
        proxies = self.node_config.list_proxies()
        workers = self.node_config.list_workers()
        components = dict(
            manager=manager,
            loggers=loggers,
            proxies=proxies,
            workers=workers
        )
        return dict(components=components), 200


class ZeekNodeConfig(Resource):

    def __init__(self):
        self.node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        self.manager = self.node_config.get_manager()
        self.loggers = self.node_config.list_loggers()
        self.proxies = self.node_config.list_proxies()
        self.workers = self.node_config.list_workers()

    def get(self, component):

        components = dict(
            manager=self.manager,
            loggers=self.loggers,
            proxies=self.proxies,
            workers=self.workers
        )
        try:
            return {component: components[component]}, 200
        except KeyError:
            return dict(
                message="Invalid component valid components are "
                        "['manager', 'loggers', 'proxies', 'workers']"), 400


class ZeekNodeWorkerConfig(Resource):
    post_fields = {
        'interface': fields.String,
        'lb_procs': fields.Integer,
        'pin_cpus': fields.List(fields.Integer)
    }

    def __init__(self):
        self.node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        self.workers = self.node_config.list_workers()

    def _create_update(self, name, verb='POST'):
        net_interfaces = utilities.get_network_interface_names()
        net_interfaces_af_fmt = ['af_packet::' + af_int for af_int in net_interfaces]
        net_interfaces.extend(net_interfaces_af_fmt)
        cpu_count = utilities.get_cpu_core_count()
        arg_parser = reqparse.RequestParser()
        if verb == 'POST':
            require_args = True
            success_code = 201
            interface = None
            lb_procs = None
            pinned_cpus = None
        else:
            worker = \
                [self.node_config.node_config[worker]
                    for worker in self.node_config.list_workers() if worker == name][0]
            require_args = False
            success_code = 200
            interface = worker['interface']
            lb_procs = worker['lb_procs']
            pinned_cpus = worker['pin_cpus']

        arg_parser.add_argument(
            'name', dest='name',
            location='json', required=False, type=str,
            help='The worker name.'
        )

        arg_parser.add_argument(
            'interface', dest='interface',
            location='json', required=require_args, type=str,
            help='The network interface to monitor; valid interfaces: {}'.format(net_interfaces)
        )
        arg_parser.add_argument(
            'lb_procs', dest='lb_procs',
            location='json', required=require_args, type=int,
            help='The number of threads the worker will use to monitor your interface.'
        )
        arg_parser.add_argument(
            'pinned_cpus', dest='pinned_cpus',
            location='json', required=require_args, type=list,
            help='A list of CPU core ids to pin; valid cores: {}'.format([c for c in range(0, cpu_count - 1)])
        )
        args = arg_parser.parse_args()
        # Rename worker operation
        if verb == 'PUT' and args.name:
            name = args.name
        if args.interface:
            interface = args.interface
        if args.pinned_cpus:
            pinned_cpus = args.pinned_cpus
        if args.lb_procs:
            lb_procs = args.lb_procs
        if interface not in net_interfaces:
            return dict(message='Invalid interface; valid interfaces: {}'.format(net_interfaces)), 400
        elif len(pinned_cpus) > cpu_count:
            return dict(message='Too many CPUs specified; cores available: {}'.format(cpu_count)), 400
        elif max(pinned_cpus) >= cpu_count:
            return dict(message='Invalid CPU core id; must be between 0 and {}'.format(cpu_count - 1)), 400
        try:
            self.node_config.add_worker(
                name=name,
                interface=interface,
                lb_procs=lb_procs,
                pin_cpus=pinned_cpus,
                host='localhost'
            )
            self.node_config.write_config()
            worker = \
                [self.node_config.node_config[worker]
                    for worker in self.node_config.list_workers() if worker == name][0]
            return dict(worker=worker), success_code
        except zeek_config.zeek_exceptions.WriteZeekConfigError as e:
            return dict(message=str(e)), 500

    def get(self, name):
        try:
            worker = [self.node_config.node_config[worker] for worker in self.workers if worker == name][0]
            return dict(worker=worker), 200
        except IndexError:
            return dict(message='Worker not found.'), 404

    def post(self, name):
        if name in self.node_config.list_workers():
            return dict(message='{} worker already exists. Use PUT to update.'.format(name)), 409
        return self._create_update(name, verb='POST')

    def put(self, name):
        if name not in self.node_config.list_workers():
            return dict(message='{} worker already does not exists. Use POST to create.'.format(name)), 400
        return self._create_update(name, verb='PUT')
