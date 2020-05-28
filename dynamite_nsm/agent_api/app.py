from flask import Flask
from flask_restful import Api
from dynamite_nsm.agent_api.resources import zeek_config

app = Flask(__name__)
api = Api(app)

api.add_resource(zeek_config.ZeekNodeComponentsList, '/zeek/config/node/')
api.add_resource(zeek_config.ZeekNodeConfig, '/zeek/config/node/<string:component>')

if __name__ == '__main__':
    app.run()
