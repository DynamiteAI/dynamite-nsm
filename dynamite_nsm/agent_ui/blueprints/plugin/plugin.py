from flask import render_template, Blueprint
from flask import redirect
from flask_security import roles_accepted


from dynamite_nsm.agent_ui.plugin_framework import load_plugin, load_plugins

plugin_blueprint = Blueprint('plugin', __name__, template_folder='templates')


@plugin_blueprint.route('/<plugin_id>')
@roles_accepted('admin', 'superuser', 'analyst')
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
