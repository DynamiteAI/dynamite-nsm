from dynamite_nsm.components.base import exceptions
from dynamite_nsm.components.base import execution_strategy


class BaseComponent:
    """
    Register a set of actions to a component
    """

    def __init__(self, component_name, component_description, config_strategy=None, install_strategy=None,
                 uninstall_strategy=None,
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

        self.config_strategy = config_strategy
        self.install_strategy = install_strategy
        self.uninstall_strategy = uninstall_strategy
        self.process_start_strategy = process_start_strategy
        self.process_stop_strategy = process_stop_strategy
        self.process_restart_strategy = process_restart_strategy
        self.process_status_strategy = process_status_strategy

        for inst in dir(self):
            if str(inst).endswith('strategy') and not str(inst) in [
                'execute_strategy',
                'validate_strategy'
            ]:
                print(inst)
                reg_func_name = 'register_' + inst
                exe_func_name = 'execute_' + inst

                def execute_strategy_function():
                    strategy = getattr(self, inst)
                    self.execute_strategy(self.component_name, strategy)

                def register_strategy_function(strategy):
                    self.validate_strategy(strategy)
                    setattr(self, inst, strategy)

                setattr(self, reg_func_name, register_strategy_function)
                setattr(self, exe_func_name, execute_strategy_function)

    @staticmethod
    def execute_strategy(component_name, strategy):
        BaseComponent.validate_strategy(strategy)
        if not strategy.functions:
            raise exceptions.StrategyNotImplemented(component_name, strategy.name)
        strategy.execute_strategy()

    @staticmethod
    def validate_strategy(strategy):
        if not strategy or not issubclass(strategy.__class__, execution_strategy.BaseExecStrategy):
            raise TypeError("Invalid strategy, must be {}.".format(type(execution_strategy.BaseExecStrategy)))

print(dir(BaseComponent('test', 'test')))