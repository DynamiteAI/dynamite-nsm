from flask import Flask
from flask_restplus import Api
from dynamite_nsm.agent_api.resources import system_info
from dynamite_nsm.agent_api.resources import zeek_config

app = Flask(__name__)
api = Api(app)

api.add_resource(system_info.SystemInfo, '/system/')
api.add_resource(system_info.CPUCoreCount, '/system/cpus/')
api.add_resource(system_info.MemoryBytes, '/system/memory/')
api.add_resource(system_info.NetworkAddresses, '/system/ips/')
api.add_resource(system_info.NetworkInterfaces, '/system/interfaces/')

api.add_resource(zeek_config.ZeekNodeComponentsList, '/zeek/config/node/')
api.add_resource(zeek_config.ZeekNodeConfig, '/zeek/config/node/<string:component>')
api.add_resource(zeek_config.ZeekNodeWorkerConfig, '/zeek/config/node/worker/<name>')

if __name__ == '__main__':
    app.run()
