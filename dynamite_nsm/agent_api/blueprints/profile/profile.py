from flask_security import roles_accepted
from sqlalchemy.exc import IntegrityError
from flask import render_template, Blueprint
from flask import request, redirect, url_for
from flask_login import logout_user, current_user

from flask_security import SQLAlchemySessionUserDatastore, UserMixin

from dynamite_nsm.agent_api import models
from dynamite_nsm.agent_api.database import db_session

user_profile_blueprint = Blueprint('profile', __name__, template_folder='templates')


def _update_user_profile(userid=None):
    user_datastore = SQLAlchemySessionUserDatastore(db_session, models.User, models.Role)
    if not userid:
        user = current_user
        return_url = url_for('profile.render_current_user_profile_form_html')
    else:
        return_url = url_for('profile.render_user_profile_form_html', userid=userid)
        user = user_datastore.find_user(id=userid)
    try:
        email = request.form['email']
        username = request.form['username']
        role = request.form['role']
        if role not in ['admin', 'superuser', 'analyst']:
            redirect(return_url)
        elif email == 'admin@dynamite.local':
            return redirect(return_url)
        elif username == 'admin':
            return redirect(return_url)
        try:
            user.username = username
            user.email = email
            db_session.commit()
        except IntegrityError:
            return redirect(return_url)
        try:

            if userid:
                user_obj = user_datastore.find_user(id=userid)
                role_obj = user_datastore.find_role(role)
                old_role_obj = user_datastore.find_role(user_obj.roles[0].name)
                user_datastore.remove_role_from_user(user_obj, old_role_obj)
                user_datastore.add_role_to_user(user_obj, role_obj)
                db_session.commit()
        except IntegrityError:
            return redirect(return_url)
    except KeyError:
        redirect(return_url)
    return redirect(return_url)


@user_profile_blueprint.route('/')
@roles_accepted('analyst', 'superuser', 'admin')
def render_current_user_profile_form_html():
    available_roles = ['admin', 'superuser', 'analyst']
    available_roles.remove(current_user.roles[0].name)
    return render_template('profile/user_profile.html', user=current_user, available_roles=available_roles,
                           api_section_hidden=False,
                           change_password_section_hidden=False)


@user_profile_blueprint.route('/<userid>')
@roles_accepted('admin')
def render_user_profile_form_html(userid):
    user_datastore = SQLAlchemySessionUserDatastore(db_session, models.User, models.Role)
    user_obj = user_datastore.find_user(id=userid)
    available_roles = ['admin', 'superuser', 'analyst']
    available_roles.remove(user_obj.roles[0].name)
    return render_template('profile/user_profile.html',
                           user=user_obj,
                           userid=int(userid),
                           available_roles=available_roles,
                           api_section_hidden=True,
                           change_password_section_hidden=int(userid) != current_user.id)


@user_profile_blueprint.route('/update_current_user_submit', methods=['POST'])
@roles_accepted('admin', 'superuser', 'analyst')
def update_current_user_form():
    return _update_user_profile(userid=None)


@user_profile_blueprint.route('/<userid>/update_user_submit', methods=['POST'])
@roles_accepted('admin')
def update_user_form(userid):
    return _update_user_profile(userid=userid)
