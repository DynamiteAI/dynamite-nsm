from flask_restplus import fields, Namespace, Resource

from dynamite_nsm.services.suricata import process as suricata_process

api = Namespace(
    name='Suricata Process',
    description='Start/Stop Monitor Suricata processes.',
)

# BASE MODELS ==========================================================================================================

model_suricata_subprocess_status = api.model('SuricataSubProcessStatus', model=dict(
    process_name=fields.String,
    process_type=fields.String(pattern='manager|logger|proxy|worker'),
    host=fields.String,
    status=fields.String(pattern='stopped|started'),
    pid=fields.Integer
))

model_suricata_process_status = api.model('SuricataProcessStatus', model=dict(
    running=fields.Boolean,
    subprocesses=fields.List(fields.Nested(model_suricata_subprocess_status))
))

# RESPONSE MODELS ======================================================================================================

# GET /
model_response_suricata_process_status = api.model('SuricataProcessStatusResponse', model=dict(
    status=fields.Nested(model_suricata_process_status)
))

# multiple endpoints
model_response_error = api.model('ErrorResponse', model={
    'message': fields.String
})

# multiple endpoints
model_response_generic_success = api.model('GenericSuccessResponse', model={
    'message': fields.String
})


@api.route('/', endpoint='suricata-status')
class SuricataStatus(Resource):

    @api.doc('get_suricata_process_status')
    @api.response(200, 'Fetched Suricata process status.', model=model_response_suricata_process_status)
    @api.response(500, 'Failed to get Suricata process status.', model=model_response_error)
    def get(self):
        try:
            suricata_p = suricata_process.ProcessManager(stdout=False, verbose=True)
            status = suricata_p.status()
            status.update({'running': status.pop('RUNNING')})
            status.update({'subprocesses': status.pop('SUBPROCESSES')})
            return dict(status=status), 200
        except suricata_process.suricata_exceptions.CallSuricataProcessError as e:
            return dict(message=e), 500


@api.route('/start', endpoint='suricata-start')
class SuricataStart(Resource):

    @api.doc('start_suricata_process')
    @api.response(200, 'Started Suricata process.', model=model_response_generic_success)
    @api.response(500, 'Failed to start Suricata process.', model=model_response_error)
    def post(self):
        try:
            suricata_p = suricata_process.ProcessManager(stdout=False, verbose=True)
            if not suricata_p.start():
                return dict(message='Failed to start Suricata process.'), 500
            return dict(message='Started Suricata.'), 200
        except suricata_process.suricata_exceptions.CallSuricataProcessError as e:
            return dict(message=e), 500


@api.route('/stop', endpoint='suricata-stop')
@api.doc('stop_suricata_process')
@api.response(200, 'Stopped Suricata process.', model=model_response_generic_success)
@api.response(500, 'Failed to stop Suricata process.', model=model_response_error)
class SuricataStop(Resource):

    def post(self):
        try:
            suricata_p = suricata_process.ProcessManager(stdout=False, verbose=True)
            if not suricata_p.stop():
                return dict(message='Failed to stop Suricata process.'), 500
            return dict(message='Stopped Suricata.'), 200
        except suricata_process.suricata_exceptions.CallSuricataProcessError as e:
            return dict(message=e), 500

