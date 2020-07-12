from flask_security.forms import LoginForm
from flask_login import current_user, login_user
from flask_restplus import fields, reqparse, Namespace, Resource


api = Namespace(
    name='Auth',
    description='Authenticate to API.',
)

# REQUEST MODELS =======================================================================================================

model_api_authentication = api.model('ApiAuthenticationRequest', model=dict(
    email=fields.String,
    password=fields.String
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

# POST /api/auth
model_response_authentication_success = api.model('ApiAuthenticationGrantSuccess', model=dict(
    token=fields.String
))


@api.route('/', endpoint='api-auth')
@api.header('Content-Type', 'application/json', required=True)
class ApiUsers(Resource):
    @api.expect(model_api_authentication)
    @api.response(201, 'Authentication Succeeded', model=model_response_authentication_success)
    @api.response(401, 'Authentication Failed', model=model_response_error)
    @api.doc('authenticate_to_api')
    def post(self):
        form = LoginForm()
        if form.validate_on_submit():
            login_user(form.user)
        try:
            return {'token': current_user.get_auth_token()}, 201
        except AttributeError:
            return {'error': 'Invalid username or password.'}, 401
