from flask import Flask
from flask_restplus import Api
from dynamite_nsm.agent_api.resources.system_info import api as system_api
from dynamite_nsm.agent_api.resources.zeek_config import api as zeek_config_api
from dynamite_nsm.agent_api.resources.suricata_config import api as suricata_api
from dynamite_nsm.agent_api.resources.zeek_scripts import api as zeek_scripts_api


app = Flask(__name__)
api = Api(app, title='Agent API', description='Configure and manage the Dynamite agent.', contact='jamin@dynamite.ai')

api.add_namespace(system_api, path='/api/system')
api.add_namespace(zeek_config_api, path='/api/zeek/config')
api.add_namespace(zeek_scripts_api, path='/api/zeek/scripts')
api.add_namespace(suricata_api, path='/api/suricata/config')

if __name__ == '__main__':
    app.run()