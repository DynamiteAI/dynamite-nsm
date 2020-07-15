from flask_security import roles_accepted
from sqlalchemy.exc import IntegrityError
from flask import render_template, Blueprint
from flask import request, redirect, url_for
from flask_login import logout_user, current_user

from dynamite_nsm.agent_api.plugin_framework import load_plugin, load_plugins

plugin_blueprint = Blueprint('plugin', __name__, template_folder='templates')


@plugin_blueprint.route('/<plugin_id>')
def render_plugin_ui_html(plugin_id):
    plugins = load_plugins(disable_load=True)
    for plugin in plugins:
        if plugin.plugin_id == plugin_id:
            return render_template(
                'plugin/plugin.html',
                plugin=load_plugin(plugin.plugin_directory),
                plugins=plugins
            )
    return redirect('/plugins')
