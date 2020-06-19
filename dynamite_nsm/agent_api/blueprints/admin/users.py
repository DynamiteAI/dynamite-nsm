from flask import request
from flask_security import roles_accepted
from flask import render_template, Blueprint
from flask_security import SQLAlchemySessionUserDatastore

from dynamite_nsm.agent_api import models
from dynamite_nsm.agent_api.database import db_session, init_db

users_blueprint = Blueprint('users', __name__, template_folder='templates')


@users_blueprint.route('/')
@roles_accepted('admin', 'tempadmin')
def list_users_html():
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
    return render_template('admin/users.html', users=users_list)


@users_blueprint.route('/create')
@roles_accepted('admin')
def create_new_user_html():
    return render_template('admin/create_new_user.html')


@users_blueprint.route('/create_initial_admin')
@roles_accepted('tempadmin')
def create_new_user_html():
    return render_template('admin/create_initial_admin.html')


@users_blueprint.route('/create_new_user')
@roles_accepted('admin')
def create_new_user():
    user_datastore = SQLAlchemySessionUserDatastore(db_session, models.User, models.Role)
    init_db()
    email = request.form.email
    username = request.form.name
    password = request.form.password
    user_datastore.create_user(email=email, username=username, password=password)
