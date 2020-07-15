from flask import flash, request, render_template, Blueprint
from flask_login import current_user
from dynamite_nsm.agent_api.plugin_framework import load_plugins

api_blueprint = Blueprint('api', __name__, template_folder='templates')


@api_blueprint.route('/')
def api():
    return render_template('api/api_dashboard.html', current_user=current_user, plugins=load_plugins(disable_load=True))
