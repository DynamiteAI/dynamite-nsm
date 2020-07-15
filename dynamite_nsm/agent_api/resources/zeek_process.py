from flask_security import roles_accepted
from flask_restplus import fields, Namespace, Resource

from dynamite_nsm.services.zeek import process as zeek_process

api = Namespace(
    name='Zeek Process',
    description='Start/Stop Monitor Zeek processes.',
)

# BASE MODELS ==========================================================================================================

model_zeek_subprocess_status = api.model('ZeekSubProcessStatus', model=dict(
    process_name=fields.String,
    process_type=fields.String(pattern='manager|logger|proxy|worker'),
    host=fields.String,
    status=fields.String(pattern='stopped|started'),
    pid=fields.Integer
))

model_zeek_process_status = api.model('ZeekProcessStatus', model=dict(
    running=fields.Boolean,
    subprocesses=fields.List(fields.Nested(model_zeek_subprocess_status))
))

# RESPONSE MODELS ======================================================================================================

# GET /
model_response_zeek_process_status = api.model('ZeekProcessStatusResponse', model=dict(
    status=fields.Nested(model_zeek_process_status)
))

# multiple endpoints
model_response_error = api.model('ErrorResponse', model={
    'message': fields.String
})

# multiple endpoints
model_response_generic_success = api.model('GenericSuccessResponse', model={
    'message': fields.String
})


@api.route('/', endpoint='zeek-status')
@api.header('Content-Type', 'application/json', required=True)
class ZeekStatus(Resource):

    @api.doc('get_zeek_process_status', security='apikey')
    @api.response(200, 'Fetched Zeek process status.', model=model_response_zeek_process_status)
    @api.response(500, 'Failed to get Zeek process status.', model=model_response_error)
    @roles_accepted('admin', 'superuser', 'analyst')
    def get(self):
        try:
            zeek_p = zeek_process.ProcessManager(stdout=False, verbose=True)
            status = zeek_p.status()
            status.update({'running': status.pop('RUNNING')})
            status.update({'subprocesses': status.pop('SUBPROCESSES')})
            return dict(status=status), 200
        except zeek_process.zeek_exceptions.CallZeekProcessError as e:
            return dict(message=e), 500


@api.route('/start', endpoint='zeek-start')
@api.header('Content-Type', 'application/json', required=True)
class ZeekStart(Resource):

    @api.doc('start_zeek_process', security='apikey')
    @api.response(200, 'Started Zeek process.', model=model_response_generic_success)
    @api.response(500, 'Failed to start Zeek process.', model=model_response_error)
    @roles_accepted('admin')
    def post(self):
        try:
            zeek_p = zeek_process.ProcessManager(stdout=False, verbose=True)
            if not zeek_p.start():
                return dict(message='Failed to start Zeek process.'), 500
            return dict(message='Started Zeek.'), 200
        except zeek_process.zeek_exceptions.CallZeekProcessError as e:
            return dict(message=e), 500


@api.route('/stop', endpoint='zeek-stop')
@api.header('Content-Type', 'application/json', required=True)
class ZeekStop(Resource):
    @api.doc('stop_zeek_process', security='apikey')
    @api.response(200, 'Stopped Zeek process.', model=model_response_generic_success)
    @api.response(500, 'Failed to stop Zeek process.', model=model_response_error)
    @roles_accepted('admin')
    def post(self):
        try:
            zeek_p = zeek_process.ProcessManager(stdout=False, verbose=True)
            if not zeek_p.stop():
                return dict(message='Failed to stop Zeek process.'), 500
            return dict(message='Stopped Zeek.'), 200
        except zeek_process.zeek_exceptions.CallZeekProcessError as e:
            return dict(message=e), 500

