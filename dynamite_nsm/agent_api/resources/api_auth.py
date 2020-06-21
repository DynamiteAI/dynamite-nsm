from flask import redirect
from flask_security import roles_accepted
from flask_restplus import Namespace, Resource


api = Namespace(
    name='Auth',
    description='Authenticate to API.',
)


@api.route('/', endpoint='api-auth')
class ApiUsers(Resource):

    @api.doc('authenticate_to_api')
    @roles_accepted('admin')
    def post(self):
        return redirect('/login')
