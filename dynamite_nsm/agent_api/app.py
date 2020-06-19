from flask import Flask
from flask_restplus import Api

from dynamite_nsm.agent_api import bootstrap
from dynamite_nsm.agent_api.blueprints.admin.users import users_blueprint
from dynamite_nsm.agent_api.blueprints.home.home import home_blueprint

from dynamite_nsm.agent_api.resources.api_users import api as users_api
from dynamite_nsm.agent_api.resources.system_info import api as system_api
from dynamite_nsm.agent_api.resources.zeek_config import api as zeek_config_api
from dynamite_nsm.agent_api.resources.zeek_process import api as zeek_process_api
from dynamite_nsm.agent_api.resources.zeek_scripts import api as zeek_scripts_api
from dynamite_nsm.agent_api.resources.zeek_profile import api as zeek_profile_api
from dynamite_nsm.agent_api.resources.suricata_rules import api as suricata_rules_api
from dynamite_nsm.agent_api.resources.suricata_config import api as suricata_config_api
from dynamite_nsm.agent_api.resources.suricata_profile import api as suricata_profile_api
from dynamite_nsm.agent_api.resources.suricata_process import api as suricata_process_api


app = Flask(__name__)
api = Api(app, doc='/api/', title='Agent API', description='Configure and manage the Dynamite agent.',
          contact='jamin@dynamite.ai')

app.register_blueprint(home_blueprint, url_prefix='/home')
app.register_blueprint(users_blueprint, url_prefix='/users')

api.add_namespace(users_api, path='/api/users')
api.add_namespace(system_api, path='/api/system')
api.add_namespace(zeek_profile_api, path='/api/zeek')
api.add_namespace(zeek_config_api, path='/api/zeek/config')
api.add_namespace(zeek_process_api, path='/api/zeek/process')
api.add_namespace(zeek_scripts_api, path='/api/zeek/scripts')
api.add_namespace(suricata_profile_api, path='/api/suricata')
api.add_namespace(suricata_rules_api, path='/api/suricata/rules')
api.add_namespace(suricata_config_api, path='/api/suricata/config')
api.add_namespace(suricata_process_api, path='/api/suricata/process')

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'

# Bcrypt is set as default SECURITY_PASSWORD_HASH, which requires a salt
app.config['SECURITY_PASSWORD_SALT'] = 'super-secret-random-salt'


@app.before_first_request
def bootstrap_users_and_roles():
    bootstrap.create_default_user_and_roles(app)


if __name__ == '__main__':
    app.run()
