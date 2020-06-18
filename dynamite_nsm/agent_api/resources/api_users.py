from flask_security import roles_accepted
from flask_restplus import fields, reqparse, Namespace, Resource
from flask_security import Security, SQLAlchemySessionUserDatastore

from dynamite_nsm.agent_api import models
from dynamite_nsm.agent_api.database import db_session, init_db, Base


api = Namespace(
    name='ApiUsers',
    description='Manage API Users.',
)


@api.route('/users', end='api-users')
class ApiUsers(Resource):

    @api.doc('list_api_users')
    #@api.response(200, 'Listed API users')
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
                    'last_login_at': user.last_login_at,
                    'current_login_at': user.current_login_at,
                    'login_count': user.login_count,
                    'active': user.active,
                    'confirmed_at': user.confirmed_at
                }
            )
            return users_list, 200
