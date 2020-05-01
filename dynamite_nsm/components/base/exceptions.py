class StrategyExecutionError(Exception):
    """
    Thrown when the number of functions does not match the number of argument groups
    """

    def __init__(self, funcs_count, arg_group_count, return_formats_count):
        """
        :param funcs_count: The number of functions
        :param arg_group_count: The number of arguments
        """
        msg = "The number of functions must equal the number of argument groups; func_count: {}, arg_count: {}, " \
              "return_formats_count: {}".format(funcs_count, arg_group_count, return_formats_count)
        super(StrategyExecutionError, self).__init__(msg)


class StrategyNotImplemented(Exception):
    """
    Thrown when no strategy has been set for a command
    """

    def __init__(self, component_name, command_name):
        """

        :param component_name: The name of the component
        :param command_name: The name of the command being executed
        """
        msg = "No strategy for {}:{}".format(component_name, command_name)
        super(StrategyNotImplemented, self).__init__(msg)
