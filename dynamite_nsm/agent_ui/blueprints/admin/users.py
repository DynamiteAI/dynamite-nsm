from flask_security import roles_accepted
from sqlalchemy.exc import IntegrityError
from flask import render_template, Blueprint
from flask import request, redirect, url_for
from flask_login import logout_user, current_user

from flask_security import SQLAlchemySessionUserDatastore

from dynamite_nsm.agent_ui import models
from dynamite_nsm.agent_ui.database import db_session
from dynamite_nsm.agent_ui.plugin_framework import load_plugins

users_blueprint = Blueprint('users', __name__, template_folder='templates')


@users_blueprint.route('/')
@roles_accepted('admin', 'tempadmin')
def list_users_html():
    users = models.User.query.all()
    users_list = []
    for user in users:
        last_login_date, current_login_date = None, None
        if user.last_login_at:
            last_login_date = user.last_login_at.strftime("%d-%b-%Y (%H:%M:%S)")
        if user.current_login_at:
            current_login_date = user.current_login_at.strftime("%d-%b-%Y (%H:%M:%S)")
        if user.email == 'managerd@dynamite.local':
            continue
        users_list.append(
            {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'role': user.roles[0].name,
                'last_login_at': last_login_date,
                'current_login_at': current_login_date,
                'login_count': user.login_count,
                'active': user.active,
                'confirmed_at': user.confirmed_at,
                'last_login_ip': user.last_login_ip
            }
        )
    return render_template('admin/users.html', users=users_list, plugins=load_plugins(disable_load=True))


@users_blueprint.route('/create')
@roles_accepted('admin')
def create_user_form_html():
    return render_template('admin/create_new_user.html',
                           plugins=load_plugins(disable_load=True))


@users_blueprint.route('/create_admin')
@roles_accepted('tempadmin')
def initial_admin_form_html():
    return render_template('admin/create_initial_admin.html')


@users_blueprint.route('/delete/<userid>', methods=['GET', 'POST'])
@roles_accepted('admin')
def delete_user_form(userid):
    if userid == current_user.id:
        return redirect('/users')
    user_datastore = SQLAlchemySessionUserDatastore(db_session, models.User, models.Role)
    user_obj = user_datastore.find_user(id=userid)
    user_datastore.delete_user(user_obj)
    db_session.commit()
    return redirect('/users')


@users_blueprint.route('/create_user_submit', methods=['POST'])
@roles_accepted('tempadmin', 'admin')
def create_new_user_form():
    user_datastore = SQLAlchemySessionUserDatastore(db_session, models.User, models.Role)
    try:
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        if role not in ['admin', 'superuser', 'analyst']:
            redirect(url_for('users.create_user_form_html'))
        elif email == 'admin@dynamite.local':
            return redirect(url_for('users.create_user_form_html'))
        elif username == 'admin':
            return redirect(url_for('users.create_user_form_html'))
        try:
            user_datastore.create_user(email=email, username=username, password=password)
            db_session.commit()
        except IntegrityError:
            return redirect(url_for('users.create_user_form_html'))
        try:
            user_obj = user_datastore.find_user(email=email)
            role_obj = user_datastore.find_role(role)
            user_datastore.add_role_to_user(user_obj, role_obj)
            db_session.commit()
        except IntegrityError:
            return redirect(url_for('users.create_user_form_html'))
    except KeyError:
        redirect(url_for('users.create_user_form_html'))
    if current_user.email == 'admin@dynamite.local':
        user_obj = user_datastore.find_user(email=current_user.email)
        user_datastore.delete_user(user_obj)
        db_session.commit()
        logout_user()
    return redirect('/home')
