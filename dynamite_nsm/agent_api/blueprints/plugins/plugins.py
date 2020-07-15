from flask_security import roles_accepted
from sqlalchemy.exc import IntegrityError
from flask import render_template, Blueprint
from flask import request, redirect, url_for
from flask_login import logout_user, current_user

from flask_security import SQLAlchemySessionUserDatastore

from dynamite_nsm.agent_api import models
from dynamite_nsm.agent_api.database import db_session
from dynamite_nsm.agent_api.plugin_framework import load_plugins

plugins_blueprint = Blueprint('plugins', __name__, template_folder='templates')


@plugins_blueprint.route('/')
def render_plugins_ui_html():
    return render_template('plugins/plugins.html', plugins=load_plugins(disable_load=True))
