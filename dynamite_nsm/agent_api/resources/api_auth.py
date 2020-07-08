from flask_security.forms import LoginForm
from flask_login import current_user, login_user
from flask_restplus import Namespace, Resource


api = Namespace(
    name='Auth',
    description='Authenticate to API.',
)


@api.route('/', endpoint='api-auth')
@api.header('Content-Type', 'application/json', required=True)
class ApiUsers(Resource):

    @api.doc('authenticate_to_api')
    def post(self):
        form = LoginForm()
        if form.validate_on_submit():
            login_user(form.user)
        try:
            return {'token': current_user.get_auth_token()}, 201
        except AttributeError:
            return {'error': 'Invalid username or password.'}, 401
