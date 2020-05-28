from flask_restful import Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.zeek import config as zeek_config

env_vars = utilities.get_environment_file_dict()
ZEEK_INSTALL_DIRECTORY = env_vars.get('ZEEK_HOME')


def err_msg(msg):
    return {'error': msg}


class ZeekNodeConfig(Resource):

    def __init__(self):
        self.node_config = zeek_config.NodeConfigManager(install_directory=ZEEK_INSTALL_DIRECTORY)

    def get(self, component='all'):
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
        if component == 'all':
            return components, 200
        else:
            try:
                return dict(component=components[component]), 200
            except KeyError:
                return err_msg(
                    "Invalid component valid components are ['manager', 'loggers', 'proxies', 'workers', 'all']"), 400


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

