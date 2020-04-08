from dynamite_nsm.components.base import exceptions


class BaseExecStrategy:

    def __init__(self, strategy_name, strategy_description):
        self.functions = []
        self.arguments = []
        self.strategy_name = strategy_name
        self.description = strategy_description

    def add_function(self, func, argument_dict):
        self.functions.append(func)
        self.arguments.append(argument_dict)

    def execute_strategy(self):
        if len(self.functions) != len(self.arguments):
            raise exceptions.StrategyExecutionError(len(self.functions), len(self.arguments))

        for i in range(0, len(self.functions)):
            func = self.functions[i]
            args = self.arguments[i]
            func(**args)


if __name__ == '__main__':

    def test_func_1(msg):
        print(msg)

    def test_func_2(num1, num2):
        print(num1 + num2)

    strategy = BaseExecStrategy()
    strategy.add_function(test_func_1, {'msg': "Hello world"})
    strategy.add_function(test_func_2, {"num1": 2, "num2": 3})
    strategy.execute_strategy()
