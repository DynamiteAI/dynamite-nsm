from flask import Flask
from flask_restplus import Api
from sqlalchemy.exc import IntegrityError
from flask_security import Security, login_required, SQLAlchemySessionUserDatastore

from dynamite_nsm.agent_api.models import User, Role
from dynamite_nsm.agent_api.database import db_session, init_db
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
api = Api(app, title='Agent API', description='Configure and manage the Dynamite agent.', contact='jamin@dynamite.ai')

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

# Setup Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
security = Security(app, user_datastore)


@app.before_first_request
def create_user():
    init_db()
    try:
        user_datastore.create_user(email='admin@dynamite.local', password='changeme')
        db_session.commit()
    except IntegrityError:
        pass



if __name__ == '__main__':
    app.run()
