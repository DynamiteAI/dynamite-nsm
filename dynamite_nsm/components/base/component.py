from dynamite_nsm.components.base import exceptions
from dynamite_nsm.components.base import execution_strategy


class BaseComponent:
    """
    Register a set of actions to a component
    """

    def __init__(self, component_name, component_description, config_strategy=None, install_strategy=None, uninstall_strategy=None,
                 process_start_strategy=None, process_stop_strategy=None, process_restart_strategy=None,
                 process_status_strategy=None):
        """
        :param component_name: The name of the component (E.G agent)
        :param component_description: A long description of the component
        :param config_strategy: An instance of an config strategy
        :param install_strategy: An instance of an install strategy
        :param uninstall_strategy: An instance of an uninstall strategy
        :param process_start_strategy: An instance of a "process start" strategy
        :param process_stop_strategy: An instance of a "process stop" strategy
        :param process_restart_strategy: An instance of a "process restart" strategy
        :param process_status_strategy: An instance of a "process status" strategy
        """

        self.component_name = component_name
        self.component_description = component_description

        self.config_strategy = None
        self.install_strategy = None
        self.uninstall_strategy = None
        self.process_start_strategy = None
        self.process_stop_strategy = None
        self.process_restart_strategy = None
        self.process_status_strategy = None

        strategies = [('config_strategy', config_strategy),
                      ('install_strategy', install_strategy),
                      ('uninstall_strategy', uninstall_strategy),
                      ('process_start_strategy', process_start_strategy),
                      ('process_stop_strategy', process_stop_strategy),
                      ('process_restart_strategy', process_restart_strategy),
                      ('process_status_strategy', process_status_strategy)]

        for strategy in strategies:
            name, value = strategy
            try:
                self.validate_strategy(value)
                setattr(self, name, value)
            except TypeError:
                pass

    @staticmethod
    def validate_strategy(strategy):
        if not strategy or not issubclass(strategy.__class__, execution_strategy.BaseExecStrategy):
            raise TypeError("Invalid strategy, must be {}.".format(type(execution_strategy.BaseExecStrategy)))

    def register_config_strategy(self, config_strategy):
        self.validate_strategy(config_strategy)
        self.config_strategy = config_strategy

    def register_install_strategy(self, install_strategy):
        self.validate_strategy(install_strategy)
        self.install_strategy = install_strategy

    def register_uninstall_strategy(self, uninstall_strategy):
        self.validate_strategy(uninstall_strategy)
        self.uninstall_strategy = uninstall_strategy

    def register_process_start_strategy(self, process_start_strategy):
        self.validate_strategy(process_start_strategy)
        self.process_start_strategy = process_start_strategy

    def register_process_stop_strategy(self, process_stop_strategy):
        self.validate_strategy(process_stop_strategy)
        self.process_stop_strategy = process_stop_strategy

    def register_process_restart_strategy(self, process_restart_strategy):
        self.validate_strategy(process_restart_strategy)
        self.process_restart_strategy = process_restart_strategy

    def register_process_status_strategy(self, process_status_strategy):
        self.validate_strategy(process_status_strategy)
        self.process_status_strategy = process_status_strategy

    def config(self):
        if not self.config_strategy.functions:
            exceptions.StrategyNotImplemented(self.component_name, "config")
        self.config_strategy.execute_strategy()

    def install(self):
        if not self.install_strategy.functions:
            exceptions.StrategyNotImplemented(self.component_name, "install")
        self.install_strategy.execute_strategy()

    def uninstall(self):
        if not self.uninstall_strategy.functions:
            exceptions.StrategyNotImplemented(self.component_name, "uninstall")
        self.uninstall_strategy.execute_strategy()

    def start(self):
        if not self.process_start_strategy.functions:
            exceptions.StrategyNotImplemented(self.component_name, "start_process")
        self.process_start_strategy.execute_strategy()

    def stop(self):
        if not self.process_stop_strategy.functions:
            exceptions.StrategyNotImplemented(self.component_name, "stop_process")
        self.process_stop_strategy.execute_strategy()

    def restart(self):
        if not self.process_restart_strategy.functions:
            exceptions.StrategyNotImplemented(self.component_name, "restart_process")
        self.process_restart_strategy.execute_strategy()

    def status(self):
        if not self.process_status_strategy.functions:
            exceptions.StrategyNotImplemented(self.component_name, "status_process")
        self.process_status_strategy.execute_strategy()
