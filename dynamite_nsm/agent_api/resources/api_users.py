from flask_security import roles_accepted
from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm.agent_api import models


api = Namespace(
    name='ApiUsers',
    description='Manage API Users.',
)


@api.route('/', endpoint='api-users')
class ApiUsers(Resource):

    @api.doc('list_api_users')
    @roles_accepted('admin')
    def get(self):
        users = models.User.query.all()
        users_list = []
        for user in users:
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
        return users_list, 200
