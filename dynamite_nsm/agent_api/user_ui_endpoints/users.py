from flask import render_template, Blueprint

from dynamite_nsm.agent_api import models

users_blueprint = Blueprint('users', __name__, template_folder='templates')


@users_blueprint.route('/')
def list_users():
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
    return render_template('templates/users.html', users=users_list)