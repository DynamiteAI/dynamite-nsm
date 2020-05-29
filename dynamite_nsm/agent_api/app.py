from flask import Flask
from flask_restplus import Api
from dynamite_nsm.agent_api.resources.system import api as system_api
from dynamite_nsm.agent_api.resources.zeek import api as zeek_config_api

app = Flask(__name__)
api = Api(app)

api.add_namespace(system_api, path='/api/system')
api.add_namespace(zeek_config_api, path='/api/zeek/config')

if __name__ == '__main__':
    app.run()