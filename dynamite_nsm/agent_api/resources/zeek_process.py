from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm.services.zeek import process as zeek_process

api = Namespace(
    name='Zeek Process',
    description='Start/Stop Monitor Zeek processes.',
)


@api.route('/', endpoint='zeek-status')
class ZeekStatus(Resource):

    def get(self):
        zeek_p = zeek_process.ProcessManager(stdout=False, verbose=True)
        status = zeek_p.status()
        return status, 200
