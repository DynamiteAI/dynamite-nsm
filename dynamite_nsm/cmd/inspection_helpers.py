import inspect
import json
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from docstring_parser import parse as docstring_parse


class ArgparseParameters:

    def __init__(self, name, **kwargs):
        """
        :param name: The name of a commandline parameter (E.G setup, stdout, verbose, any_func_name)
        :param kwargs: A list of kwargs accepted by argparse.ArgumentParser.add_argument method
        """
        self.name = name
        self.flags = ['--' + self.name.replace('_', '-')]
        self.kwargs = kwargs

    def __str__(self):
        args = self.kwargs.copy()
        args.update({'dest': self.name, 'flags': self.flags})
        return json.dumps({k: str(v) for k, v in args.items()})

    @classmethod
    def create_from_typing_annotation(cls, name, python_type, default: Optional[Any] = None,
                                      required: Optional[bool] = False):
        """
        Convenience method for creating argparse parameters from a python <class type>

        :param name: The name of the commandline parameter
        :param python_type: The datatype that best describes the parameter
        :param default: The default value for the parameter being evaluated
        """
        return cls(name, **cls.derive_params_from_type_annotation(python_type, default=default, required=required))

    @staticmethod
    def derive_params_from_type_annotation(python_type: Any, default: Optional[Any] = None,
                                           required: Optional[bool] = False) -> Dict:
        """
        :param python_type: A <class 'type'> or typing derived class
        :param default: The default value for the parameter being evaluated
        :return: A dictionary of supported **kwargs
        """
        python_type = str(python_type)
        action, default, nargs = None, default, None
        _type = str
        if default:
            required = False
        if 'Union' in python_type and 'NoneType' in python_type:
            required = False
        if 'Optional' in python_type:
            required = False
        if 'List' in python_type:
            nargs = '+'
        if 'list' in python_type:
            nargs = '+'
        if 'bool' in python_type:
            action = 'store_true'
            _type = None
        elif 'int' in python_type:
            _type = int
        elif 'float' in python_type:
            _type = float
        elif 'str' in python_type:
            _type = str
        derived_args = dict(
            required=required,
            action=action,
            default=default,
            nargs=nargs,
            type=_type
        )

        derived_args = {k: v for k, v in derived_args.items() if v is not None and v != ''}
        return derived_args

    def add_description(self, description):
        self.kwargs['help'] = description

    def add_flag(self, flag: str):
        self.flags.append(flag)


def get_argparse_parameters(func_def: Tuple[str, dict, str], defaults: Optional[Dict]) -> List[ArgparseParameters]:
    """
    Given a callable function returns a list of argparse compatible arguments

    :param func_def: A tuple containing the function.__name__, function.__annotations__, inspect.getdoc(function)
    :param defaults: A dictionary where the key a parameter name and the value represents the value to default it too.

    :return: A list of ArgparseParameters
    """
    argparse_parameter_group = []
    param_map = {}
    _, annotations, docs = func_def
    docstring_params = docstring_parse(docs).params

    for doc_param in docstring_params:
        _, arg_name = doc_param.args
        param_map[arg_name] = doc_param.description
    for param_name, data_type in annotations.items():
        argparse_params = ArgparseParameters.create_from_typing_annotation(name=param_name, python_type=data_type)
        if param_name == 'return':
            continue
        if defaults and defaults.get(param_name):
            argparse_params = ArgparseParameters.create_from_typing_annotation(name=param_name, python_type=data_type,
                                                                               default=defaults.get(param_name))
        try:
            argparse_params.add_description(param_map[param_name])
        except KeyError:
            pass
        argparse_parameter_group.append(argparse_params)
    return argparse_parameter_group


def get_class_instance_methods(cls: object, defaults: Optional[Dict] = None, use_parent_init: Optional[bool] = True) ->\
        Tuple[List[ArgparseParameters], Dict[str, List[ArgparseParameters]]]:
    """
    Given a class retrieves all the methods with their corresponding parameters

    :param cls: The class that you wish to enumerate
    :param use_parent_init: If True, the parent class' init arguments will be scanned as well
    :param defaults: A dictionary where the key a parameter name and the value represents the value to default it too.
    :return: A tuple containing the base_params for the __init__ method in the first position; and a dictionary
             containing a map of remaining function names to lists of their corresponding parameters
             (E.G {func_name: [ArgparseParameters, ArgparseParam...], func_name_2: [ArgparseParameters, Argp...]})
    """
    base_params = None
    interface_functions = {}

    # Enumerate the class instance methods as well as any parent classes instance methods
    for c in cls.__mro__:
        for callable in c.__dict__.values():
            func_def = get_function_definition(callable)
            if not func_def:
                continue
            else:
                # func_name, annotations, docs
                func_name, _, _ = func_def
                if func_name == '__init__':
                    continue
                # Store the rest of our method parameters in a dictionary
                # {func_name: [ArgparseParameters, ArgparseParam...], func_name_2: [ArgparseParameters, Argp...]}
                else:
                    interface_functions[func_name] = get_argparse_parameters(func_def, defaults=defaults)
            # and parent class is selected
    try:
        parent_class = cls.__mro__[1]
    except IndexError:
        parent_class = cls
    if use_parent_init:
        func_def = get_function_definition(parent_class.__init__)
    else:
        func_def = get_function_definition(cls.__init__)
    base_params = get_argparse_parameters(func_def, defaults=defaults)

    return base_params, interface_functions


def get_function_definition(func: Callable) -> Union[Tuple[str, dict, str], None]:
    """
    Given a callable function returns a three part definition for that function

    :param func: A callable function
    :return: A tuple with the (function.__name__, function.__annotations__, inspect.getdoc(function))
    """
    if not isinstance(func, Callable):
        return None
    if func.__name__ == '__init__':
        name = '__init__'
        annotations = dict(inspect.signature(func).parameters.items())
        annotations.pop('self')
        docs = inspect.getdoc(func)
    else:
        try:
            name, annotations = func.__name__, func.__annotations__
            docs = inspect.getdoc(func)
        except AttributeError:
            return None
    return name, annotations, docs