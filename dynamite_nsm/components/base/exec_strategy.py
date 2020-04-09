import json
from dynamite_nsm.components.base import exceptions


def print_json_message(msg_obj):
    print(json.dumps(msg_obj, indent=1))


class BaseExecStrategy:

    def __init__(self, strategy_name, strategy_description, functions=(), arguments=(), return_formats=()):
        self.strategy_name = strategy_name
        self.strategy_description = strategy_description

        self.functions = list(functions)
        self.arguments = list(arguments)
        self.return_formats = list(return_formats)

        if len(self.functions) != len(self.arguments) != len(self.return_formats):
            raise exceptions.StrategyExecutionError(len(self.functions), len(self.arguments), len(return_formats))

    @classmethod
    def create(cls, strategy_name, strategy_description, functions=(), arguments=(), return_formats=()):
        exec_strat = cls(strategy_name, strategy_description)
        for i in range(0, len(functions)):
            exec_strat.add_function(functions[i], arguments[i], return_format=return_formats[i])
        return exec_strat

    def add_function(self, func, argument_dict, return_format=None):
        self.functions.append((func, return_format))
        self.arguments.append(argument_dict)

    def execute_strategy(self):
        for i in range(0, len(self.functions)):
            func, ret_fmt = self.functions[i]
            args = self.arguments[i]
            if not ret_fmt:
                func(**args)
            elif str(ret_fmt).lower() == "json":
                print_json_message(func(**args))


if __name__ == '__main__':

    def test_func_1(msg):
        print(msg)

    def test_func_2(num1, num2):
        print(num1 + num2)

    strategy = BaseExecStrategy("test_strategy", "Test Strategy")
    strategy.add_function(test_func_1, {'msg': "Hello world"})
    strategy.add_function(test_func_2, {"num1": 2, "num2": 3})
    strategy.execute_strategy()
