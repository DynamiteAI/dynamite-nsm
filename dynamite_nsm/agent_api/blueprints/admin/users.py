from flask import request, redirect
from flask_security import roles_accepted
from flask import render_template, Blueprint
from flask_security import SQLAlchemySessionUserDatastore
from sqlalchemy.exc import IntegrityError

from dynamite_nsm.agent_api import models
from dynamite_nsm.agent_api.database import db_session

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
def new_user_form_html():
    return render_template('admin/create_new_user.html')


@users_blueprint.route('/create_initial_admin')
@roles_accepted('tempadmin')
def initial_admin_form_html():
    return render_template('admin/create_initial_admin.html')


@users_blueprint.route('/create_new_user', methods=['POST'])
@roles_accepted('tempadmin')
def create_new_user_form():
    user_datastore = SQLAlchemySessionUserDatastore(db_session, models.User, models.Role)
    try:
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        if role not in ['admin', 'superuser', 'analyst']:
            redirect('/users/create_new_user')
        elif username == 'admin':
            redirect('/users/create_new_user')
        elif email == 'admin@dynamite.local':
            redirect('/users/create_new_user')
        try:
            user_datastore.create_user(email=email, username=username, password=password)
            db_session.commit()
        except IntegrityError:
            redirect('/users/create_new_user')
        try:
            user_obj = user_datastore.find_user(email=email)
            role_obj = user_datastore.find_role(role)
            user_datastore.add_role_to_user(user_obj, role_obj)
            db_session.commit()
        except IntegrityError:
            redirect('/users/create_new_user')
    except KeyError:
        redirect('/users/create_new_user')
    return redirect('/users')
