from flask import Flask
from flask_restful import Api
from dynamite_nsm.agent_api.resources.zeek_config import ZeekNodeConfig

app = Flask(__name__)
api = Api(app)

api.add_resource(ZeekNodeConfig, '/zeek/config/node/')

if __name__ == '__main__':
    app.run()
