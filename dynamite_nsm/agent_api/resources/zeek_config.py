from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.agent_api import validators
from dynamite_nsm.services.zeek import config as zeek_config

api = Namespace(
    name='Zeek Configuration',
    description='Configure Zeek Network Settings.',
)

env_vars = utilities.get_environment_file_dict()
ZEEK_INSTALL_DIRECTORY = env_vars.get('ZEEK_HOME')

model_zeek_simple_node_component = api.model(
    'ZeekSimpleNodeComponent', model=dict(
        type=fields.String,
        name=fields.String,
        host=fields.String
    )
)

model_zeek_worker_node_component = api.model('ZeekWorkerNodeComponent', dict(
    type=fields.String,
    name=fields.String,
    interface=fields.String,
    lb_method=fields.String,
    lb_procs=fields.String,
    pin_cpus=fields.String,
    host=fields.String
))

model_zeek_node_components = api.model(
    'ZeekNodeComponents', model={
        'manager': fields.Nested(model_zeek_simple_node_component),
        'loggers': fields.List(fields.Nested(model_zeek_simple_node_component)),
        'proxies': fields.List(fields.Nested(model_zeek_simple_node_component)),
        'workers': fields.List(fields.Nested(model_zeek_worker_node_component)),
    }
)

# multiple endpoints
model_response_error = api.model('ErrorResponse', model={
    'message': fields.String
})

# multiple endpoints
model_response_generic_success = api.model('GenericSuccessResponse', model={
    'message': fields.String
})

# GET /config
model_response_list_components_response = api.model('ZeekNodeComponentsResponse', model={
    'components': fields.Nested(model_zeek_node_components)
})

# GET /config/<component>
model_response_get_component = api.model(name='ZeekGetComponentResponse', model={
    'components': fields.List(fields.Nested(model_zeek_simple_node_component))
})

# GET /config/manager
model_response_get_manager_component = api.model('ZeekGetManagerComponentResponse', model={
    'manager': fields.Nested(model_zeek_simple_node_component)
})

# GET /config/loggers/<name>
model_response_get_logger_component = api.model('ZeekGetLoggerComponentResponse', model={
    'loggers': fields.List(fields.Nested(model_zeek_simple_node_component))
})

# GET /config/proxies/<name>
model_response_get_proxy_component = api.model('ZeekGetProxyComponentResponse', model={
    'proxies': fields.List(fields.Nested(model_zeek_simple_node_component))
})

# GET /config/workers/<name>
model_response_get_worker_component = api.model('ZeekGetWorkerComponentResponse', model={
    'worker': fields.Nested(model_zeek_worker_node_component)
})


@api.route('/', endpoint='node-configs')
class ZeekNodeComponentsList(Resource):

    @api.doc('list_node_components')
    @api.response(200, 'Listed components.',
                  model=model_response_list_components_response)
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


@api.route('/<component>', endpoint='node-config')
class ZeekNodeConfig(Resource):

    @api.doc('get_node_component')
    @api.param('component', description='The type of the component: manager, loggers, proxies, workers')
    @api.response(200, 'Fetched Zeek node component.', model=model_response_get_component)
    @api.response(400, 'Invalid Zeek node component.', model=model_response_error)
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


@api.route('/manager', endpoint='node-manager')
class ZeekNodeManagerManager(Resource):

    @staticmethod
    def _update():
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        manager_name = node_config.get_manager()
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'name', dest='name',
            location='json', required=True, type=str,
            help='The manager name.'
        )

        args = arg_parser.parse_args()
        if not validators.validate_name(args.name):
            return dict(
                message='Invalid "name"; must be between 5 and 30 characters and match '
                        '"^[a-zA-Z0-9]([\w -]*[a-zA-Z0-9]$)"'), 400
        # Rename manager operation
        try:
            node_config.add_manager(
                name=args.name,
                host='localhost'
            )
            if args.name != manager_name:
                node_config.remove_manager(manager_name)
                node_config.write_config()
            manager_name = node_config.get_manager()
            manager = dict(
                name=manager_name,
                type='manager',
                host='localhost'
            )
            return dict(manager=manager), 200
        except zeek_config.zeek_exceptions.WriteZeekConfigError as e:
            return dict(message=str(e)), 500

    @api.doc('get_manager')
    @api.response(200, 'Get Zeek manager.', model=model_response_get_manager_component)
    def get(self):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        manager_name = node_config.get_manager()
        manager = dict(
            name=manager_name,
            type='manager',
            host='localhost'
        )
        return manager, 200

    @api.doc('update_manager')
    @api.param('name', description='The name of the manager.')
    @api.response(200, 'Updated Zeek manager.', model=model_response_get_manager_component)
    @api.response(400, 'One or more parameters are incorrect.', model=model_response_error)
    @api.response(500, 'An error occurred on the server.', model=model_response_error)
    def put(self):
        return self._update()


@api.route('/loggers/<name>', endpoint='logger-manager')
class ZeekNodeLoggerManager(Resource):

    @staticmethod
    def _create_update(name, verb='POST'):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        arg_parser = reqparse.RequestParser()
        if verb == 'POST':
            success_code = 201
        else:
            success_code = 200

        arg_parser.add_argument(
            'name', dest='name',
            location='json', required=True, type=str,
            help='The logger name.'
        )

        args = arg_parser.parse_args()

        # Rename logger operation
        if verb == 'PUT' and args.name:
            if not validators.validate_name(args.name):
                return dict(
                    message='Invalid "name"; must be between 5 and 30 characters and match '
                            '"^[a-zA-Z0-9]([\w -]*[a-zA-Z0-9]$)"'), 400
            node_config.remove_logger(name)
            name = args.name
        try:
            node_config.add_logger(
                name=name,
                host='localhost'
            )
            node_config.write_config()
            logger = \
                [node_config.node_config[logger]
                 for logger in node_config.list_loggers() if logger == name][0]
            logger.update({'name': name})
            return dict(logger=logger), success_code
        except zeek_config.zeek_exceptions.WriteZeekConfigError as e:
            return dict(message=str(e)), 500

    @api.doc('delete_logger')
    @api.param('name', description='The name of the logger.')
    @api.response(200, 'Deleted Zeek logger.', model=model_response_generic_success)
    @api.response(404, 'Could not find Zeek logger.', model=model_response_error)
    def delete(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        found = False
        for logger in node_config.list_loggers():
            if logger == name:
                found = True
                break
        if not found:
            return dict(message='Logger not found.'), 404
        else:
            node_config.remove_logger(name)
            node_config.write_config()
            return dict(message='Deleted logger {}.'.format(name)), 200

    @api.doc('get_logger')
    @api.param('name', description='The name of the logger.')
    @api.response(200, 'Fetched Zeek logger.', model=model_response_get_logger_component)
    @api.response(404, 'Could not find Zeek logger.', model=model_response_error)
    def get(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        try:
            logger = [node_config.node_config[logger] for logger in node_config.list_loggers() if logger == name][0]
            logger.update({'name': name})
            return dict(logger=logger), 200
        except IndexError:
            return dict(message='Logger not found.'), 404

    @api.doc('create_logger')
    @api.param('name', description='The name of the logger.')
    @api.response(201, 'Created Zeek logger.', model=model_response_get_logger_component)
    @api.response(400, 'One or more parameters are incorrect.', model=model_response_error)
    @api.response(409, 'A logger of that name already exists.', model=model_response_error)
    @api.response(500, 'An error occurred on the server.', model=model_response_error)
    def post(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        if name in node_config.list_loggers():
            return dict(message='{} logger already exists. Use PUT to update.'.format(name)), 409
        return self._create_update(name, verb='POST')

    @api.doc('update_logger')
    @api.param('name', description='The name of the logger.')
    @api.response(200, 'Updated Zeek logger.', model=model_response_get_logger_component)
    @api.response(400, 'One or more parameters are incorrect.', model=model_response_error)
    @api.response(404, 'Could not find Zeek logger.', model=model_response_error)
    @api.response(500, 'An error occurred on the server.', model=model_response_error)
    def put(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        if name not in node_config.list_loggers():
            return dict(message='{} logger does not exists. Use POST to create.'.format(name)), 400
        return self._create_update(name, verb='PUT')


@api.route('/proxies/<name>', endpoint='proxy-manager')
class ZeekNodeProxyManager(Resource):

    @staticmethod
    def _create_update(name, verb='POST'):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        arg_parser = reqparse.RequestParser()
        if verb == 'POST':
            success_code = 201
        else:
            success_code = 200

        arg_parser.add_argument(
            'name', dest='name',
            location='json', required=True, type=str,
            help='The proxy name.'
        )

        args = arg_parser.parse_args()

        # Rename proxy operation
        if verb == 'PUT' and args.name:
            if not validators.validate_name(args.name):
                return dict(
                    message='Invalid "name"; must be between 5 and 30 characters and match '
                            '"^[a-zA-Z0-9]([\w -]*[a-zA-Z0-9]$)"'), 400
            node_config.remove_logger(name)
            name = args.name
        try:
            node_config.add_logger(
                name=name,
                host='localhost'
            )
            node_config.write_config()
            proxy = \
                [node_config.node_config[proxy]
                 for proxy in node_config.list_proxies() if proxy == name][0]
            proxy.update({'name': name})
            return dict(proxy=proxy), success_code
        except zeek_config.zeek_exceptions.WriteZeekConfigError as e:
            return dict(message=str(e)), 500

    @api.doc('delete_proxy')
    @api.param('name', description='The name of the proxy.')
    @api.response(200, 'Deleted Zeek proxy.', model=model_response_generic_success)
    @api.response(404, 'Could not find Zeek proxy.', model=model_response_error)
    def delete(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        found = False
        for proxy in node_config.list_proxies():
            if proxy == name:
                found = True
                break
        if not found:
            return dict(message='Logger not found.'), 404
        else:
            node_config.remove_logger(name)
            node_config.write_config()
            return dict(message='Deleted proxy {}.'.format(name)), 200

    @api.doc('get_proxy')
    @api.param('name', description='The name of the proxy.')
    @api.response(200, 'Fetched Zeek proxy.', model=model_response_get_proxy_component)
    @api.response(404, 'Could not find Zeek proxy.', model=model_response_error)
    def get(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        try:
            proxy = [node_config.node_config[proxy] for proxy in node_config.list_proxies() if proxy == name][0]
            proxy.update({'name': name})
            return dict(proxy=proxy), 200
        except IndexError:
            return dict(message='Logger not found.'), 404

    @api.doc('create_proxy')
    @api.param('name', description='The name of the proxy.')
    @api.response(201, 'Created Zeek proxy.', model=model_response_get_proxy_component)
    @api.response(400, 'One or more parameters are incorrect.', model=model_response_error)
    @api.response(409, 'A proxy of that name already exists.', model=model_response_error)
    @api.response(500, 'An error occurred on the server.', model=model_response_error)
    def post(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        if name in node_config.list_proxies():
            return dict(message='{} proxy already exists. Use PUT to update.'.format(name)), 409
        return self._create_update(name, verb='POST')

    @api.doc('update_proxy')
    @api.param('name', description='The name of the proxy.')
    @api.response(200, 'Updated Zeek proxy.', model=model_response_get_proxy_component)
    @api.response(400, 'One or more parameters are incorrect.', model=model_response_error)
    @api.response(404, 'Could not find Zeek proxy.', model=model_response_error)
    @api.response(500, 'An error occurred on the server.', model=model_response_error)
    def put(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        if name not in node_config.list_proxies():
            return dict(message='{} proxy does not exists. Use POST to create.'.format(name)), 400
        return self._create_update(name, verb='PUT')


@api.route('/workers/<name>', endpoint='worker-manager')
class ZeekNodeWorkerManager(Resource):

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
            if not validators.validate_name(args.name):
                return dict(
                    message='Invalid "name"; must be between 5 and 30 characters and match '
                            '"^[a-zA-Z0-9]([\w -]*[a-zA-Z0-9]$)"'), 400
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
            worker.update({'name': name})
            return dict(worker=worker), success_code
        except zeek_config.zeek_exceptions.WriteZeekConfigError as e:
            return dict(message=str(e)), 500

    @api.doc('delete_worker')
    @api.param('name', description='The name of the worker.')
    @api.response(200, 'Deleted Zeek worker.', model=model_response_generic_success)
    @api.response(404, 'Could not find Zeek worker.', model=model_response_error)
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
    @api.response(200, 'Fetched Zeek worker.', model=model_response_get_worker_component)
    @api.response(404, 'Could not find Zeek worker.', model=model_response_error)
    def get(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        try:
            worker = [node_config.node_config[worker] for worker in node_config.list_workers() if worker == name][0]
            worker.update({'name': name})
            return dict(worker=worker), 200
        except IndexError:
            return dict(message='Worker not found.'), 404

    @api.doc('create_worker')
    @api.param('name', description='The name of the worker.')
    @api.response(201, 'Created Zeek worker.', model=model_response_get_worker_component)
    @api.response(400, 'One or more parameters are incorrect.', model=model_response_error)
    @api.response(409, 'A worker of that name already exists.', model=model_response_error)
    @api.response(500, 'An error occurred on the server.', model=model_response_error)
    def post(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        if name in node_config.list_workers():
            return dict(message='{} worker already exists. Use PUT to update.'.format(name)), 409
        return self._create_update(name, verb='POST')

    @api.doc('update_worker')
    @api.param('name', description='The name of the worker.')
    @api.response(200, 'Updated Zeek worker.', model=model_response_get_worker_component)
    @api.response(400, 'One or more parameters are incorrect.', model=model_response_error)
    @api.response(404, 'Could not find Zeek worker.', model=model_response_error)
    @api.response(500, 'An error occurred on the server.', model=model_response_error)
    def put(self, name):
        node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        if name not in node_config.list_workers():
            return dict(message='{} worker does not exists. Use POST to create.'.format(name)), 400
        return self._create_update(name, verb='PUT')
