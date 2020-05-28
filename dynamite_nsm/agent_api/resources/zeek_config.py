from flask_restful import fields, reqparse, marshal_with,  Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.zeek import config as zeek_config

env_vars = utilities.get_environment_file_dict()
ZEEK_INSTALL_DIRECTORY = env_vars.get('ZEEK_HOME')


class ZeekNodeComponentsList(Resource):

    def __init__(self):
        self.node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)

    def get(self):
        manager = self.node_config.get_manager()
        loggers = self.node_config.list_loggers()
        proxies = self.node_config.list_proxies()
        workers = self.node_config.list_workers()
        components = dict(
            manager=manager,
            loggers=loggers,
            proxies=proxies,
            workers=workers
        )
        return dict(components=components), 200


class ZeekNodeConfig(Resource):

    def __init__(self):
        self.node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        self.manager = self.node_config.get_manager()
        self.loggers = self.node_config.list_loggers()
        self.proxies = self.node_config.list_proxies()
        self.workers = self.node_config.list_workers()

    def get(self, component):

        components = dict(
            manager=self.manager,
            loggers=self.loggers,
            proxies=self.proxies,
            workers=self.workers
        )
        try:
            return {component: components[component]}, 200
        except KeyError:
            return dict(
                error="Invalid component valid components are "
                      "['manager', 'loggers', 'proxies', 'workers']"), 400


class ZeekNodeWorkerConfig(Resource):

    def __init__(self):
        self.node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)
        self.workers = self.node_config.list_workers()

    def get(self, name):
        try:
            worker = [self.node_config.node_config[worker] for worker in self.workers if worker == name][0]
            return dict(worker=worker), 200
        except IndexError:
            return dict(error='Worker not found.'), 404



