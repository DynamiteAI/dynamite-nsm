from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm.services.zeek import process as zeek_process

api = Namespace(
    name='Zeek Process',
    description='Start/Stop Monitor Zeek processes.',
)


@api.route('/', endpoint='zeek-status')
class ZeekStatus(Resource):

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
class ZeekStart(Resource):

    def post(self):
        try:
            zeek_p = zeek_process.ProcessManager(stdout=False, verbose=True)
            if not zeek_p.start():
                return dict(message='Failed to start Zeek process.'), 500
            return dict(message='Started Zeek.'), 200
        except zeek_process.zeek_exceptions.CallZeekProcessError as e:
            return dict(message=e), 500

