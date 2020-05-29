from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities

from dynamite_nsm.services.zeek import config as zeek_config

api = Namespace(
    name='zeek_config',
    description='Configure and control Zeek installation.',
)

env_vars = utilities.get_environment_file_dict()
ZEEK_INSTALL_DIRECTORY = env_vars.get('ZEEK_HOME')

zeek_simple_node_component = api.model(
    'SIMPLE_ZEEK_NODE_COMPONENT', model=dict(
        type=fields.String,
        host=fields.String
    )
)

zeek_worker_node_component = api.model('ZEEK_NODE_WORKER_COMPONENT', dict(
    type=fields.String,
    interface=fields.String,
    lb_method=fields.String,
    lb_procs=fields.String,
    pin_cpus=fields.String,
    host=fields.String
))

# multiple endpoints
response_error = dict(
    message=fields.String
)

# multiple endpoints

response_success = dict(
    message=fields.String
)

# GET /config
response_list_components_model = dict(
    components=dict(
        manager=fields.Nested(zeek_simple_node_component),
        loggers=fields.List(fields.Nested(zeek_simple_node_component)),
        proxies=fields.List(fields.Nested(zeek_simple_node_component)),
        workers=fields.List(fields.Nested(zeek_worker_node_component)),
    )
)

# GET /config/<component>
response_get_component_model = dict(
    component=fields.List(fields.Nested(zeek_simple_node_component))
)

response_get_worker_component_model = dict(
    worker=fields.Nested(zeek_worker_node_component)
)


@api.route('/', endpoint='zeek-components')
class ZeekNodeComponentsList(Resource):

    @api.doc('list_node_components')
    @api.response(200, 'Listed components.',
                  model=api.model(name='LISTED_ZEEK_COMPONENTS_SUCCESS',
                                  model=response_list_components_model))
    def get(self):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        manager = node_config.get_manager()
        loggers = node_config.list_loggers()
        proxies = node_config.list_proxies()
        workers = node_config.list_workers()
        components = dict(
            manager=manager,
            loggers=loggers,
            proxies=proxies,
            workers=workers
        )
        return dict(components=components), 200


@api.route('/<component>', endpoint='component-configurations')
class ZeekNodeConfig(Resource):

    @api.doc('get_node_component')
    @api.param('component', description='The type of the component: manager, loggers, proxies, workers')
    @api.response(200, 'Fetched Zeek node component.',
                  api.model(name='FETCHED_ZEEK_COMPONENT_SUCCESS',
                            model=response_get_component_model))
    @api.response(400, 'Invalid Zeek node component.',
                  api.model(name='VALIDATION_ERROR', model=response_error))
    def get(self, component):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        manager = node_config.get_manager()
        loggers = node_config.list_loggers()
        proxies = node_config.list_proxies()
        workers = node_config.list_workers()
        components = dict(
            manager=manager,
            loggers=loggers,
            proxies=proxies,
            workers=workers
        )
        try:
            return {component: components[component]}, 200
        except KeyError:
            return dict(
                message="Invalid component valid components are "
                        "['manager', 'loggers', 'proxies', 'workers']"), 400


@api.route('/workers/<name>', endpoint='worker-configuration')
class ZeekNodeWorkerConfig(Resource):

    @staticmethod
    def _create_update(name, verb='POST'):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
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
                [node_config.node_config[worker]
                 for worker in node_config.list_workers() if worker == name][0]
            require_args = False
            success_code = 200
            interface = worker['interface']
            lb_procs = int(worker['lb_procs'])
            pinned_cpus = [int(c) for c in worker['pin_cpus'].split(',')]

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
            help='A list of CPU core ids to pin; valid cores: {}'.format([c for c in range(0, cpu_count)])
        )
        args = arg_parser.parse_args()

        # Rename worker operation
        if verb == 'PUT' and args.name:
            node_config.remove_worker(name)
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
            return dict(message='Invalid CPU core id; must be between 0 and {}'.format(cpu_count)), 400
        try:
            node_config.add_worker(
                name=name,
                interface=interface,
                lb_procs=lb_procs,
                pin_cpus=pinned_cpus,
                host='localhost'
            )
            node_config.write_config()
            worker = \
                [node_config.node_config[worker]
                 for worker in node_config.list_workers() if worker == name][0]
            return dict(worker=worker), success_code
        except zeek_config.zeek_exceptions.WriteZeekConfigError as e:
            return dict(message=str(e)), 500

    @api.doc('delete_worker')
    @api.param('name', description='The name of the worker.')
    @api.response(200, 'Deleted Zeek worker.',
                  model=api.model(name='DELETED_ZEEK_WORKER_SUCCESS',
                                  model=response_success))
    @api.response(404, 'Could not find Zeek worker.',
                  model=api.model(name='NOT_FOUND_ERROR', model=response_error))
    def delete(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        found = False
        for worker in node_config.list_workers():
            if worker == name:
                found = True
                break
        if not found:
            return dict(message='Worker not found.'), 404
        else:
            node_config.remove_worker(name)
            node_config.write_config()
            return dict(message='Deleted worker {}.'.format(name)), 200

    @api.doc('get_worker')
    @api.param('name', description='The name of the worker.')
    @api.response(200, 'Fetched Zeek worker.',
                  model=api.model(name='FETCHED_ZEEK_WORKER_SUCCESS',
                                  model=response_get_worker_component_model))
    @api.response(404, 'Could not find Zeek worker.',
                  model=api.model(name='NOT_FOUND_ERROR', model=response_error))
    def get(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        try:
            worker = [node_config.node_config[worker] for worker in node_config.list_workers() if worker == name][0]
            return dict(worker=worker), 200
        except IndexError:
            return dict(message='Worker not found.'), 404

    @api.doc('create_worker')
    @api.param('name', description='The name of the worker.')
    @api.response(201, 'Created Zeek worker.',
                  model=api.model(name='FETCHED_ZEEK_WORKER_SUCCESS',
                                  model=response_get_worker_component_model))
    @api.response(400, 'One or more parameters are incorrect.',
                  model=api.model(name='VALIDATION_ERROR', model=response_error))
    @api.response(409, 'A worker of that name already exists.',
                  model=api.model(name='ALREADY_EXISTS_ERROR',
                                  model=response_error))
    @api.response(500, 'An error occurred on the server.',
                  model=api.model(name='SERVER_ERROR', model=response_error))
    def post(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        if name in node_config.list_workers():
            return dict(message='{} worker already exists. Use PUT to update.'.format(name)), 409
        return self._create_update(name, verb='POST')

    @api.doc('update_worker')
    @api.param('name', description='The name of the worker.')
    @api.response(200, 'Updated Zeek worker.',
                  model=api.model(name='FETCHED_ZEEK_WORKER_SUCCESS',
                                  model=response_get_worker_component_model))
    @api.response(400, 'One or more parameters are incorrect.',
                  model=api.model(name='VALIDATION_ERROR', model=response_error))
    @api.response(404, 'Could not find Zeek worker.',
                  model=api.model(name='NOT_FOUND_ERROR', model=response_error))
    @api.response(500, 'An error occurred on the server.',
                  model=api.model(name='SERVER_ERROR', model=response_error))
    def put(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        if name not in node_config.list_workers():
            return dict(message='{} worker does not exists. Use POST to create.'.format(name)), 400
        return self._create_update(name, verb='PUT')
