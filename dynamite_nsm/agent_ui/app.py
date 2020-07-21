from flask_restplus import Api
from flask import Flask, request, redirect
from flask_fontawesome import FontAwesome

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.agent_ui import bootstrap

from dynamite_nsm.agent_ui.blueprints.api.api import api_blueprint
from dynamite_nsm.agent_ui.blueprints.home.home import home_blueprint
from dynamite_nsm.agent_ui.blueprints.admin.users import users_blueprint
from dynamite_nsm.agent_ui.blueprints.admin.plugins import plugins_blueprint
from dynamite_nsm.agent_ui.blueprints.profile.profile import user_profile_blueprint
from dynamite_nsm.agent_ui.blueprints.bug_report.bug_report import bug_report_blueprint

from dynamite_nsm.agent_ui.resources.api_auth import api as auth_api
from dynamite_nsm.agent_ui.resources.api_users import api as users_api
from dynamite_nsm.agent_ui.resources.system_info import api as system_api
from dynamite_nsm.agent_ui.blueprints.plugin.plugin import plugin_blueprint
from dynamite_nsm.agent_ui.resources.zeek_config import api as zeek_config_api
from dynamite_nsm.agent_ui.resources.zeek_process import api as zeek_process_api
from dynamite_nsm.agent_ui.resources.zeek_scripts import api as zeek_scripts_api
from dynamite_nsm.agent_ui.resources.zeek_profile import api as zeek_profile_api
from dynamite_nsm.agent_ui.resources.suricata_rules import api as suricata_rules_api
from dynamite_nsm.agent_ui.resources.filebeat_config import api as filebeat_config_api
from dynamite_nsm.agent_ui.resources.suricata_config import api as suricata_config_api
from dynamite_nsm.agent_ui.resources.filebeat_profile import api as filebeat_profile_api
from dynamite_nsm.agent_ui.resources.suricata_profile import api as suricata_profile_api
from dynamite_nsm.agent_ui.resources.suricata_process import api as suricata_process_api
from dynamite_nsm.agent_ui.resources.filebeat_process import api as filebeat_process_api


authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization-Token'
    }
}

app = Flask(__name__, static_folder='ui/static', static_url_path='/static')
FontAwesome(app)
api = Api(app, doc='/api/', title='Agent API', description='Configure and manage the Dynamite agent.',
          security='apikey', authorizations=authorizations, contact='jamin@dynamite.ai')

app.url_map.strict_slashes = False
app.register_blueprint(api_blueprint, url_prefix='/docs/')
app.register_blueprint(home_blueprint, url_prefix='/home')
app.register_blueprint(users_blueprint, url_prefix='/users')
app.register_blueprint(user_profile_blueprint, url_prefix='/user')
app.register_blueprint(plugin_blueprint, url_prefix='/plugin')
app.register_blueprint(plugins_blueprint, url_prefix='/plugins')
app.register_blueprint(bug_report_blueprint, url_prefix='/bug-report')

api.add_namespace(auth_api, path='/api/auth')
api.add_namespace(users_api, path='/api/users')
api.add_namespace(system_api, path='/api/system')

api.add_namespace(zeek_profile_api, path='/api/zeek')
api.add_namespace(zeek_config_api, path='/api/zeek/config')
api.add_namespace(zeek_scripts_api, path='/api/zeek/scripts')
api.add_namespace(zeek_process_api, path='/api/zeek/process')

api.add_namespace(suricata_profile_api, path='/api/suricata')
api.add_namespace(suricata_config_api, path='/api/suricata/config')
api.add_namespace(suricata_rules_api, path='/api/suricata/rules')
api.add_namespace(suricata_process_api, path='/api/suricata/process')

api.add_namespace(filebeat_profile_api, path='/api/filebeat')
api.add_namespace(filebeat_config_api, path='/api/filebeat/config')
api.add_namespace(filebeat_process_api, path='/api/filebeat/process')

app.config['DEBUG'] = True
app.config['UPLOAD_FOLDER'] = const.INSTALL_CACHE
app.config['SECURITY_TRACKABLE'] = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['APPLICATION_ROOT'] = "/"
app.config['SECURITY_CHANGEABLE'] = True
app.config['SECURITY_POST_LOGIN_VIEW'] = "/home"
app.config['SECURITY_POST_LOGOUT_VIEW'] = "/home"
app.config['SECURITY_SEND_PASSWORD_CHANGE_EMAIL'] = False
app.config['SECURITY_POST_CHANGE_VIEW'] = "/home"
app.config['WTF_CSRF_ENABLED'] = False

# Bcrypt is set as default SECURITY_PASSWORD_HASH, which requires a salt
app.config['SECURITY_PASSWORD_SALT'] = 'super-secret-random-salt'

utilities.makedirs(const.INSTALL_CACHE, exist_ok=True)


@app.before_first_request
def bootstrap_users_and_roles():
    bootstrap.create_default_user_and_roles(app)


@app.before_request
def redirect_to_home():
    if request.path == '/':
        return redirect('/home')


if __name__ == '__main__':
    app.run()
