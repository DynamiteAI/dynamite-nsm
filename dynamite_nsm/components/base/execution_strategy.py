import json
from dynamite_nsm.components.base import exceptions


def print_json_message(msg_obj):
    print(json.dumps(msg_obj, indent=1))


class BaseExecStrategy:
    """Register a set of functions to be executed in defined order"""

    def __init__(self, strategy_name, strategy_description, functions=(), arguments=(), return_formats=()):
        """
        :param strategy_name: The name of the strategy
        :param strategy_description: A long description of the strategy
        :param functions: A list of functions (<type:function>) to be called
        :param arguments: A list of adjacent arguments (<type:list<<type: dict>>)
        :param return_formats: A list of the return types to print (E.G [None, None, 'json'])
        """
        self.strategy_name = strategy_name
        self.strategy_description = strategy_description

        self.functions = list(functions)
        self.arguments = list(arguments)
        self.return_formats = list(return_formats)

        if len(self.functions) != len(self.arguments) != len(self.return_formats):
            raise exceptions.StrategyExecutionError(len(self.functions), len(self.arguments), len(return_formats))

    def add_function(self, func, argument_dict, return_format=None):
        """
        Alternative method of adding function to execute

        :param func: A <type:function> function to be called
        :param argument_dict: A <type: dict> of corresponding arguments
        :param return_format: The return type to print
        """
        self.functions.append(func)
        self.arguments.append(argument_dict)
        self.return_formats.append(return_format)

    def execute_strategy(self):
        """
        Run your functions with corresponding arguments and return formats.
        """
        for i in range(0, len(self.functions)):
            func = self.functions[i]
            args = self.arguments[i]
            ret_fmt = self.return_formats[i]
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
