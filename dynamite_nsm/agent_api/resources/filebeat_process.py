from flask_security import roles_accepted
from flask_restplus import fields, Namespace, Resource

from dynamite_nsm.services.filebeat import process as filebeat_process

api = Namespace(
    name='Filebeat Process',
    description='Start/Stop Monitor Filebeat processes.',
)

# BASE MODELS ==========================================================================================================


model_filebeat_process_status = api.model('FilebeatProcessStatus', model=dict(
    running=fields.Boolean,
    pid=fields.Integer,
    log=fields.String
))

# RESPONSE MODELS ======================================================================================================

# GET /
model_response_filebeat_process_status = api.model('FilebeatProcessStatusResponse', model=dict(
    status=fields.Nested(model_filebeat_process_status)
))

# multiple endpoints
model_response_error = api.model('ErrorResponse', model={
    'message': fields.String
})

# multiple endpoints
model_response_generic_success = api.model('GenericSuccessResponse', model={
    'message': fields.String
})


@api.route('/', endpoint='filebeat-status')
@api.header('Content-Type', 'application/json', required=True)
class FilebeatStatus(Resource):

    @api.doc('get_filebeat_process_status', security='apikey')
    @api.response(200, 'Fetched Filebeat process status.', model=model_response_filebeat_process_status)
    @api.response(500, 'Failed to get Filebeat process status.', model=model_response_error)
    @roles_accepted('admin', 'superuser', 'analyst')
    def get(self):
        try:
            filebeat_p = filebeat_process.ProcessManager(stdout=False, verbose=True)
            status = filebeat_p.status()
            status.update({'running': status.pop('RUNNING')})
            status.update({'pid': status.pop('PID')})
            status.update({'log': status.pop('LOGS')})
            return dict(status=status), 200
        except filebeat_process.filebeat_exceptions.CallFilebeatProcessError as e:
            return dict(message=e), 500


@api.route('/start', endpoint='filebeat-start')
@api.header('Content-Type', 'application/json', required=True)
class FilebeatStart(Resource):

    @api.doc('start_filebeat_process', security='apikey')
    @api.response(200, 'Started Filebeat process.', model=model_response_generic_success)
    @api.response(500, 'Failed to start Filebeat process.', model=model_response_error)
    @roles_accepted('admin', 'superuser')
    def post(self):
        try:
            filebeat_p = filebeat_process.ProcessManager(stdout=False, verbose=True)
            if not filebeat_p.start():
                return dict(message='Failed to start Filebeat process.'), 500
            return dict(message='Started Filebeat.'), 200
        except filebeat_process.filebeat_exceptions.CallFilebeatProcessError as e:
            return dict(message=e), 500


@api.route('/stop', endpoint='filebeat-stop')
@api.header('Content-Type', 'application/json', required=True)
class FilebeatStop(Resource):
    @api.doc('stop_filebeat_process', security='apikey')
    @api.response(200, 'Stopped Filebeat process.', model=model_response_generic_success)
    @api.response(500, 'Failed to stop Filebeat process.', model=model_response_error)
    @roles_accepted('admin', 'superuser')
    def post(self):
        try:
            filebeat_p = filebeat_process.ProcessManager(stdout=False, verbose=True)
            if not filebeat_p.stop():
                return dict(message='Failed to stop Filebeat process.'), 500
            return dict(message='Stopped Filebeat.'), 200
        except filebeat_process.filebeat_exceptions.CallFilebeatProcessError as e:
            return dict(message=e), 500
