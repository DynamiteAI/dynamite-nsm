import inspect
import json
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from docstring_parser import parse as docstring_parse


class ArgparseParameters:
    """
    Represent the **kwargs that can be provided to the `argparse.ArgumentParser` class
    """

    def __init__(self, name, **kwargs):
        """Setup from a dictionary
        Args:
            name: The name of a commandline parameter (E.G setup, stdout, verbose, any_func_name)
            kwargs: A list of kwargs accepted by argparse.ArgumentParser.add_argument method
        """
        self.name = name
        self.flags = ['--' + self.name.replace('_', '-')]
        self.kwargs = kwargs

    def __str__(self):
        args = self.kwargs.copy()
        args.update({'dest': self.name, 'flags': self.flags})
        return json.dumps({k: str(v) for k, v in args.items()})

    @classmethod
    def create_from_typing_annotation(cls, name: str, python_type: type, default: Optional[Any] = None,
                                      required: Optional[bool] = True):
        """Convenience method for creating argparse parameters from a python <class type>
        Args:
            name: The name of the commandline parameter
            python_type: The datatype that best describes the parameter
            default: The default value for the parameter being evaluated
            required: If True, argparse will interpret this argument as required
        Returns:
            None
        """

        return cls(name, **cls.derive_params_from_type_annotation(python_type, default=default, required=required))

    @staticmethod
    def derive_params_from_type_annotation(python_type: Any, default: Optional[Any] = None,
                                           required: Optional[bool] = True) -> Dict:
        """Convert from a typing annotation string to an `argparse.ArgumentParser` `type`
        Args:
            python_type: A <class 'type'> or typing derived class
            default: The default value for the parameter being evaluated
            required: If true, the `required` parameter will be added to the parameter dictionary
        Returns:
             A dictionary of supported **kwargs used to instantiate an `argparse.ArgumentParser` object
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
    """Given a callable function returns a list of argparse compatible arguments
    Args:
        func_def: A tuple containing the `function.__name__`, `function.__annotations__`, `inspect.getdoc(function)`
        defaults: A dictionary where the key a parameter name and the value represents the value to default it too.
    Returns:
         A list of `ArgparseParameters`
    """
    argparse_parameter_group = []
    param_map = {}
    _, annotations, docs = func_def
    try:
        docstring_params = docstring_parse(docs).params
    except ValueError as e:
        newline_delim_doc_str = '\\n'.join(docs.split('\n'))
        raise Exception(
            f'Docs: {newline_delim_doc_str} failed to parse: {e} likely because this docstring has a '
            f'newline in it somewhere.')

    for doc_param in docstring_params:
        _, arg_name = doc_param.args
        if '***' in doc_param.description:
            split_token = '***'
        elif '---' in docstring_params:
            split_token = '---'
        else:
            split_token = '___'

        # If an explicit line break is detected in our docstrings we don't parse parameters passed that line break.

        param_map[arg_name] = doc_param.description.split(split_token)[0]
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


def get_class_instance_methods(cls: object, defaults: Optional[Dict] = None, use_parent_init: Optional[bool] = True) -> \
        Tuple[List[ArgparseParameters], Dict[str, List[ArgparseParameters]]]:
    """Given a class retrieves all the methods with their corresponding parameters
    Args:
        cls: The class that you wish to enumerate
        use_parent_init: If True, the parent class' init arguments will be scanned as well
        defaults: A dictionary where the key a parameter name and the value represents the value to default it too.
    Returns:
         A tuple containing the base_params for the __init__ method in the first position; and a dictionary containing a
          map of remaining function names to lists of their corresponding parameters
          (E.G `{func_name [ArgparseParameters, ArgparseParam...], func_name_2 [ArgparseParameters, Argp...]}`)
    """
    interface_functions = {}

    # Enumerate the class instance methods as well as any parent classes instance methods
    try:
        method_resolution_order = cls.__mro__
    except AttributeError:
        method_resolution_order = cls.__class__.__mro__
    for c in method_resolution_order:
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
                    # Look first in the top level class then parent classes
                    if func_name not in interface_functions.keys():
                        interface_functions[func_name] = get_argparse_parameters(func_def, defaults=defaults)
            # and parent class is selected
    try:
        parent_class = method_resolution_order[1]
    except IndexError:
        parent_class = cls
    if use_parent_init:
        func_def = get_function_definition(parent_class.__init__)
    else:
        func_def = get_function_definition(cls.__init__)
    base_params = get_argparse_parameters(func_def, defaults=defaults)

    return base_params, interface_functions


def get_function_definition(func: Callable) -> Union[Tuple[str, dict, str], None]:
    """Given a callable function returns a three part definition for that function
    Args:
        func: A callable function
    Returns:
         A tuple with the (`function.__name__`, `function.__annotations__`, `inspect.getdoc(function)`)
    """
    if not isinstance(func, Callable):
        return None
    if func.__name__ == '__init__':
        name = '__init__'
        annotations = dict(inspect.signature(func).parameters.items())
        annotations.pop('self', None)
        docs = inspect.getdoc(func)
    else:
        try:
            name, annotations = func.__name__, func.__annotations__
            docs = inspect.getdoc(func)
        except AttributeError:
            return None
    return name, annotations, docs
