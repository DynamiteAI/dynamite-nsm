from flask_restplus import fields, reqparse, Namespace, Resource
from flask_security import roles_accepted
from flask_login import current_user

from dynamite_nsm import utilities
from dynamite_nsm.agent_api import validators
from dynamite_nsm.services.filebeat import config as filebeat_config

api = Namespace(
    name='FileBeat Configuration',
    description='Configure FileBeat Settings.',
)

env_vars = utilities.get_environment_file_dict()
FILEBEAT_INSTALL_DIRECTORY = env_vars.get('FILEBEAT_HOME')

# BASE MODELS ==========================================================================================================
model_filebeat_config_output_properties = api.model('FilebeatConfigOutputProperties', model=dict(
    enabled=fields.Boolean,
    hosts=fields.List(fields.String)
))

model_filebeat_config_output = api.model('FilebeatConfigOutput', model=dict(
    logstash=fields.Nested(model_filebeat_config_output_properties),
    kafka=fields.Nested(model_filebeat_config_output_properties)
))

model_filebeat_config = api.model('FilebeatConfig', model=dict(
    agent_tag=fields.String,
    outputs=fields.Nested(model_filebeat_config_output),
    monitored_paths=fields.List(fields.String)
))

model_filebeat_kafka_config = api.model('FilebeatKafkaConfig', model=dict(
    enabled=fields.Boolean,
    hosts=fields.List(fields.String),
    topic=fields.String,
    username=fields.String,
))

model_filebeat_logstash_config = api.model('FilebeatLogstashConfig', model=dict(
    enabled=fields.Boolean,
    hosts=fields.List(fields.String)
))

# REQUEST MODELS =======================================================================================================

model_request_create_kafka = api.model('FilebeatKafkaCreateRequest', model=dict(
    hosts=fields.List(fields.String(required=True, pattern='\w+[:]\d+'), required=True),
    topic=fields.String(required=True),
    username=fields.String(required=False),
    password=fields.String(required=False)
))

model_request_create_logstash = api.model('FilebeatLogstashCreateRequest', model=dict(
    hosts=fields.List(fields.String(required=True, pattern='\w+[:]\d+'))
))

model_request_filebeat_update_output_status = api.model('FilebeatUpdateStatusRequest', model=dict(
    status=fields.String(pattern='enabled|disabled')
))

model_request_create_agent_tag = api.model('FilebeatAgentTagCreateRequest', model=dict(
    tag=fields.String(required=True, pattern='^[a-zA-Z0-9_]{5,30}$')
))



# RESPONSE MODELS ======================================================================================================

# multiple endpoints
model_response_error = api.model('ErrorResponse', model={
    'message': fields.String
})

# multiple endpoints
model_response_generic_success = api.model('GenericSuccessResponse', model={
    'message': fields.String
})

# GET /
model_response_filebeat_config = api.model('FilebeatConfigResponse', model=dict(
    config=fields.Nested(model_filebeat_config)
))

model_response_filebeat_kafka_config = api.model('FilebeatKafkaConfigResponse', model=dict(
    kafka=fields.Nested(model_filebeat_kafka_config)
))

model_response_filebeat_logstash_config = api.model('FilebeatLogstashConfigResponse', model=dict(
    logstash=fields.Nested(model_filebeat_logstash_config)
))

model_response_agent_tag = api.model('FilebeatAgentTagResponse', model=dict(
    tag=fields.String,
))


@api.route('/', endpoint='filebeat-config')
@api.header('Content-Type', 'application/json', required=True)
class FileBeatConfig(Resource):

    @api.doc('fetch_filebeat_config', security='apikey')
    @api.response(200, 'Fetched Config.', model=model_response_filebeat_config)
    @roles_accepted('admin', 'superuser')
    def get(self):
        beats_config = filebeat_config.ConfigManager(FILEBEAT_INSTALL_DIRECTORY)

        config = dict(
            agent_tag=beats_config.get_agent_tag(),
            outputs=dict(
                logstash={'enabled': beats_config.is_logstash_output_enabled(),
                          'hosts': beats_config.get_logstash_target_hosts()},
                kafka={'enabled': beats_config.is_kafka_output_enabled(),
                       'hosts': beats_config.get_kafka_target_hosts()}
            )
        )
        if current_user.has_role('admin'):
            config.update({
                'monitored_files': beats_config.get_monitor_target_paths()
            })
        return dict(config=config), 200


@api.route('/kafka', endpoint='filebeat-kafka-manager')
@api.header('Content-Type', 'application/json', required=True)
class FileBeatKafkaManager(Resource):

    @api.doc('fetch_filebeat_kafka_config', security='apikey')
    @api.response(200, 'Fetched Config.', model=model_response_filebeat_kafka_config)
    @roles_accepted('admin', 'superuser')
    def get(self):
        beats_config = filebeat_config.ConfigManager(FILEBEAT_INSTALL_DIRECTORY)
        kafka_targets = beats_config.get_kafka_target_config()
        del kafka_targets['password']
        return dict(kafka=kafka_targets), 200

    @api.doc('create_filebeat_kafka_config', security='apikey')
    @api.response(201, 'Created Config.', model=model_response_filebeat_kafka_config)
    @api.response(400, 'Invalid config parameter format.', model=model_response_error)
    @api.expect(model_request_create_kafka)
    @roles_accepted('admin')
    def post(self):
        beats_config = filebeat_config.ConfigManager(FILEBEAT_INSTALL_DIRECTORY)
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'hosts', dest='hosts', location='json', type=list, required=True,
            help='A list of upstream Kafka brokers (E.G ["192.168.0.9:9092", "my-external-kafka-cluster:9092"]). '
        )
        arg_parser.add_argument(
            'topic', dest='topic',
            location='json', type=str, required=True,
            help='The Kafka topic to send messages to.'
        )
        arg_parser.add_argument(
            'username', dest='username',
            location='json', type=str,
            help='The username for logging into Kafka.'
        )
        arg_parser.add_argument(
            'password', dest='password',
            location='json', type=str,
            help='The password for logging into Kafka.'
        )
        args = arg_parser.parse_args()

        if not validators.validate_filebeat_targets(args.hosts):
            return dict(
                message='Invalid host format. Valid format must contain both port and IP/host'
                        ' (E.G ["192.168.0.9:9092", "my-external-kafka-cluster:9092"])'), 400
        beats_config.set_kafka_targets(args.hosts, args.topic, args.username, args.password)
        try:
            beats_config.write_config()
        except filebeat_config.filebeat_exceptions.WriteFilebeatConfigError as e:
            return dict(message=str(e)), 500
        kafka_targets = beats_config.get_kafka_target_config()
        del kafka_targets['password']
        return dict(kafka=kafka_targets), 201

    @api.doc('update_status_filebeat_kafka_config', security='apikey')
    @api.response(200, 'Updated Config', model=model_response_filebeat_kafka_config)
    @api.response(400, 'Invalid config parameter format.', model=model_response_error)
    @api.expect(model_request_filebeat_update_output_status)
    @roles_accepted('admin')
    def put(self):
        beats_config = filebeat_config.ConfigManager(FILEBEAT_INSTALL_DIRECTORY)
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'status', dest='status',
            location='json', required=True, type=str, choices=['enabled', 'disabled', 'enable', 'disable'],
            help='Enable/Disable a output configuration.'
        )
        args = arg_parser.parse_args()
        if args.status == 'enabled' or args.status == 'enable':
            beats_config.enable_kafka_output()
        else:
            beats_config.disable_kafka_output()
        try:
            beats_config.write_config()
        except filebeat_config.filebeat_exceptions.WriteFilebeatConfigError as e:
            return dict(message=str(e)), 500
        kafka_targets = beats_config.get_kafka_target_config()
        del kafka_targets['password']
        return dict(kafka=kafka_targets), 200


@api.route('/logstash', endpoint='filebeat-logstash-manager')
@api.header('Content-Type', 'application/json', required=True)
class FileBeatLogstashManager(Resource):

    @api.doc('fetch_filebeat_logstash_config', security='apikey')
    @api.response(200, 'Fetched Config.', model=model_response_filebeat_logstash_config)
    @roles_accepted('admin', 'superuser')
    def get(self):
        beats_config = filebeat_config.ConfigManager(FILEBEAT_INSTALL_DIRECTORY)
        logstash_targets = beats_config.get_logstash_target_config()
        return dict(logstash=logstash_targets), 200

    @api.doc('update_status_filebeat_logstash_config', security='apikey')
    @api.response(200, 'Updated Config', model=model_response_filebeat_logstash_config)
    @api.response(400, 'Invalid config parameter format.', model=model_response_error)
    @api.expect(model_request_filebeat_update_output_status)
    @roles_accepted('admin')
    def put(self):
        beats_config = filebeat_config.ConfigManager(FILEBEAT_INSTALL_DIRECTORY)
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'status', dest='status',
            location='json', required=True, type=str, choices=['enabled', 'disabled', 'enable', 'disable'],
            help='Enable/Disable a output configuration.'
        )
        args = arg_parser.parse_args()
        if args.status == 'enabled' or args.status == 'enable':
            beats_config.enable_logstash_output()
        else:
            beats_config.disable_logstash_output()
        try:
            beats_config.write_config()
        except filebeat_config.filebeat_exceptions.WriteFilebeatConfigError as e:
            return dict(message=str(e)), 500
        logstash_targets = beats_config.get_logstash_target_config()
        return dict(logstash=logstash_targets), 200

    @api.doc('create_filebeat_logstash_config', security='apikey')
    @api.response(201, 'Created Config.', model=model_response_filebeat_logstash_config)
    @api.response(400, 'Invalid config parameter format.', model=model_response_error)
    @api.expect(model_request_create_logstash)
    @roles_accepted('admin')
    def post(self):
        beats_config = filebeat_config.ConfigManager(FILEBEAT_INSTALL_DIRECTORY)
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'hosts', dest='hosts', location='json', type=list, required=True,
            help='A list of upstream LogStash server (E.G ["192.168.0.9:5044", "my-external-logstash-server:5044"]). '
        )
        args = arg_parser.parse_args()

        if not validators.validate_filebeat_targets(args.hosts):
            return dict(
                message='Invalid host format. Valid format must contain both port and IP/host'
                        ' (E.G ["192.168.0.9:5044", "my-external-logstash-server:5044"])'), 400
        beats_config.set_logstash_targets(args.hosts)
        try:
            beats_config.write_config()
        except filebeat_config.filebeat_exceptions.WriteFilebeatConfigError as e:
            return dict(message=str(e)), 500
        logstash_targets = beats_config.get_logstash_target_config()
        return dict(logstash=logstash_targets), 201


@api.route('/tag', endpoint='filebeat-agent-tag-manager')
@api.header('Content-Type', 'application/json', required=True)
class FileBeatAgentTagManager(Resource):

    @api.doc('fetch_filebeat_tag', security='apikey')
    @api.response(200, 'Fetched Config.', model=model_response_agent_tag)
    @roles_accepted('admin', 'superuser')
    def get(self):
        beats_config = filebeat_config.ConfigManager(FILEBEAT_INSTALL_DIRECTORY)
        return dict(tag=beats_config.get_agent_tag()), 200

    @api.doc('create_filebeat_tag', security='apikey')
    @api.response(201, 'Created Config.', model=model_response_agent_tag)
    @api.response(400, 'Invalid tag format', model=model_response_error)
    @api.expect(model_request_create_agent_tag)
    @roles_accepted('admin')
    def post(self):
        beats_config = filebeat_config.ConfigManager(FILEBEAT_INSTALL_DIRECTORY)
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'tag', dest='tag',
            location='json', type=str, required=True,
            help='A tag representing the segment this agent is monitoring. (E.G web_servers, user_environment)'
        )
        args = arg_parser.parse_args()
        if not filebeat_config.ConfigManager.validate_agent_tag(args.tag):
            return dict(
                message='Invalid agent tag format. Valid format must be alphanumeric and underscores only characters '
                        'and be between 5 and 30 characters in length.'), 400
        beats_config.set_agent_tag(args.tag)
        try:
            beats_config.write_config()
        except filebeat_config.filebeat_exceptions.WriteFilebeatConfigError as e:
            return dict(message=str(e)), 500
        return dict(tag=beats_config.get_agent_tag()), 201
