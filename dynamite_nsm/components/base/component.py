from dynamite_nsm.components.base import exceptions
from dynamite_nsm.components.base import execution_strategy


class BaseComponent:
    """
    Register a set of actions to a component
    """

    def __init__(self, component_name, component_description, **strategies):
        """

        The Base Component works by dynamically generating a set of methods at runtime via reflection based on the
        **strategies kwargs.

        The user can provide of **strategies either pre-registered
        (by setting the argument equal to an execution_strategy.BaseExecStrategy derived class) OR can set these
        arguments to None. Either way, for each strategy a corresponding set of functions will be created:

        For example:
        **strategies: install_strategy=None, uninstall_strategy=None

        Will result in 4 instance methods being created:

            register_install_strategy & register_uninstall_strategy
                (That provide the ability to activate these strategies)

            execute_install_strategy & execute_uninstall_strategy
                (That provide the ability to run these strategies once activated)

        :param component_name: The name of the component (E.G agent)
        :param component_description: A long description of the component
        :param strategies: Execution strategy names and their corresponding values
               (E.G install_strategy=execution_strategy.InstallStrategy())
               MUST END IN "_strategy" TO BE RECOGNIZED
        """

        self.component_name = component_name
        self.component_description = component_description

        # For each of our strategies (**keyword_args); set up instance variables
        for name, value in strategies.items():
            setattr(self, name, value)

        # For every instance variable ending in _strategy, dynamically create two functions:
        #     register_$(strategy_var)
        #     execute_$(strategy_var)

        for inst in dir(self):
            if str(inst).endswith('strategy') and not str(inst) in [
                'execute_strategy',
                'validate_strategy'
            ]:
                reg_func_name = 'register_' + inst
                exe_func_name = 'execute_' + inst

                def execute_strategy_function():
                    """
                    Execute a strategy
                    """

                    strategy = getattr(self, inst)
                    self.execute_strategy(self.component_name, strategy)

                def register_strategy_function(strategy):
                    """
                    Register a strategy

                    :param strategy: An instance of a execution_strategy.BaseExecutionStrategy derived class
                    """
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
            raise TypeError("Invalid strategy, must be {}.".format(execution_strategy.BaseExecStrategy))
