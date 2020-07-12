from flask_security import roles_accepted
from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm.agent_api import models


api = Namespace(
    name='Users',
    description='Manage API Users.',
)

# BASE MODELS ==========================================================================================================

model_api_user = api.model('ApiUser', model=dict(
    id=fields.String,
    email=fields.String,
    username=fields.String,
    last_login_at=fields.String,
    current_login_at=fields.String,
    login_count=fields.Integer,
    confirmed_at=fields.String
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

# POST /api/users
model_response_api_users = api.model('ListApiUsersResponse', model=dict(
    users=fields.List(fields.Nested(model_api_user))
))


@api.route('/', endpoint='api-users')
@api.header('Content-Type', 'application/json', required=True)
class ApiUsers(Resource):

    @api.doc('list_api_users')
    @api.response(200, 'Listed users', model=model_response_api_users)
    @roles_accepted('admin')
    def get(self):
        users = models.User.query.all()
        users_list = []
        for user in users:
            if user.email == 'managerd@dynamite.local':
                continue
            users_list.append(
                {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'last_login_at': str(user.last_login_at),
                    'current_login_at': str(user.current_login_at),
                    'login_count': user.login_count,
                    'active': user.active,
                    'confirmed_at': user.confirmed_at
                }
            )
        return dict(users=users_list), 200
