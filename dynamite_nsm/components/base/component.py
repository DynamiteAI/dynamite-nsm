from dynamite_nsm.components.base import exceptions
from dynamite_nsm.components.base import execution_strategy


class BaseComponent:

    def __init__(self, component_name, component_description, install_strategy=None, uninstall_strategy=None,
                 process_start_strategy=None, process_stop_strategy=None, process_restart_strategy=None,
                 process_status_strategy=None):

        self.component_name = component_name
        self.component_description = component_description

        self.install_strategy = None
        self.uninstall_strategy = None
        self.process_start_strategy = None
        self.process_stop_strategy = None
        self.process_restart_strategy = None
        self.process_status_strategy = None

        strategies = [('install_strategy', install_strategy),
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
        if not issubclass(strategy, execution_strategy.BaseExecStrategy):
            raise TypeError("Invalid strategy, must be {}.".format(type(execution_strategy.BaseExecStrategy)))

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

    def register_process_status_strategy(self, process_status_strategy):
        self.validate_strategy(process_status_strategy)
        self.process_status_strategy = process_status_strategy

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
