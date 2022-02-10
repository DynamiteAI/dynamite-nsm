import json
import os
import logging
from typing import Callable, Dict, List, Optional, Union

from yaml import SafeDumper
from yaml import dump

from tabulate import tabulate

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as exceptions


class NoAliasDumper(SafeDumper):
    def ignore_aliases(self, data):
        return True


class BackupConfigManager:
    """
    Manage backup and restoration process across various service configs
    """

    def __init__(self, backup_directory: str):
        if not utilities.is_setup():
            raise exceptions.DynamiteNotSetupError()
        self.backup_directory = backup_directory

    def list_backup_configs(self) -> List:
        """List configuration backups

        Returns:
             A list of dictionaries with the following keys ["name", "path", "timestamp"]
        """
        return utilities.list_backup_configurations(self.backup_directory)

    def restore_backup_config(self, backup_name: str, restore_name: str):
        """
        Restore a configuration from our config store

        :param backup_name: The name of the configuration file or the keyword "recent" which will restore the most recent backup.
        :param restore_name: The name of the configuration file to write too
        :return: True, if successful
        """
        if backup_name == "recent":
            configs = self.list_backup_configs()
            if configs:
                return utilities.restore_backup_configuration(configs[0]['filepath'], restore_name)
        return utilities.restore_backup_configuration(
            os.path.join(self.backup_directory, backup_name), restore_name)


class GenericConfigManager:

    def __init__(self, config_data: Dict, name: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """
        A catchall configuration manager, generic enough to work on any configuration like file
        Args:
            config_data: Configuration data dictionary
            name: The name of the configuration
            verbose: Include detailed debug messages
            stdout: Print output to console
        """
        if not utilities.is_setup():
            raise exceptions.DynamiteNotSetupError()
        self.config_data = config_data
        self.formatted_data = json.dumps(config_data)
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.stdout = stdout
        self.verbose = verbose
        self.logger = get_logger(str(name), level=log_level, stdout=stdout)

    def add_parser(self, parser: Callable, attribute_name):
        setattr(self, attribute_name, parser(self.config_data))

    def reset(self, out_file_path: Optional[str], default_config_path: Optional[str]):
        """Reset a configuration file back to its default
        Args:
        out_file_path: The path to the output file
            default_config_path: The path to the default configuration

        Returns:
            None
        """
        self.logger.info(f'Restoring {out_file_path} to default state.')
        with open(default_config_path, 'r') as default_conf_f_in:
            with open(out_file_path, 'w') as conf_f_out:
                conf_f_out.write(default_conf_f_in.read())
        if utilities.is_root():
            utilities.set_ownership_of_file(out_file_path)

    def commit(self, out_file_path: str, backup_directory: Optional[str] = None) -> None:
        """Write out an updated configuration file, and optionally backup the old one.
        Args:
            out_file_path: The path to the output file
            backup_directory: The path to the backup directory
        Returns:
            None
        """

        # Backup old configuration first
        out_file_name = os.path.basename(out_file_path)
        backup_file_name = out_file_name + '.backup'
        if backup_directory:
            utilities.backup_configuration_file(out_file_path, backup_directory,
                                                destination_file_prefix=backup_file_name)
        try:
            with open(out_file_path, 'w') as config_raw_f:
                config_raw_f.write(self.formatted_data)
            if utilities.is_root():
                utilities.set_ownership_of_file(out_file_path)
        except IOError as e:
            raise exceptions.WriteConfigError(f'An error occurred while writing the configuration file to disk. {e}')
        self.logger.warning('Configuration updated. Restart this service to apply.')

    def get_printable_config(self) -> Dict:
        """
        Get the configuration as a dictionary object
        Returns:
            A dictionary of config keys and values
        """
        variables = {}
        for var in vars(self):
            if var.startswith('_'):
                continue
            variables[var] = str(getattr(self, var))
        return variables


class JavaOptionsConfigManager(GenericConfigManager):
    """
    A special base configuration manager for jvm.options configurations
    """

    @staticmethod
    def _parse_jvm_options(data: Dict):
        initial_memory = None
        maximum_memory = None
        extra_params = []
        for line in data['data']:
            line = str(line).replace(' ', '')
            if line.startswith('-Xms'):
                initial_memory = line.replace('-Xms', '').strip()
            elif line.startswith('-Xmx'):
                maximum_memory = line.replace('-Xmx', '').strip()
            elif line.startswith('#') or line.strip() == '':
                continue
            else:
                extra_params.append(line.strip())
        return initial_memory, maximum_memory, extra_params

    def __init__(self, config_data: Dict, name: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """Work with jvm.options configurations
        Args:
            config_data: Configuration data dictionary
            name: The name of the configuration
            verbose: Include detailed debug messages
            stdout: Print output to console
        """
        super().__init__(config_data, name=name, verbose=verbose, stdout=stdout)

        self.initial_memory = None
        self.maximum_memory = None
        self._raw_extra_params = None

        self.add_parser(
            parser=lambda data: self._parse_jvm_options(data)[0],
            attribute_name='initial_memory'
        )
        self.add_parser(
            parser=lambda data: self._parse_jvm_options(data)[1],
            attribute_name='maximum_memory'
        )

        self.add_parser(
            parser=lambda data: self._parse_jvm_options(data)[2],
            attribute_name='_raw_extra_params'
        )

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        """Write out an updated configuration file, and optionally backup the old one.
        Args:
            out_file_path: The path to the output file; if none given overwrites existing
            backup_directory: The path to the backup directory
        Returns:
            None
        """

        # Backup old configuration first
        out_file_name = os.path.basename(out_file_path)
        backup_file_name = out_file_name + '.backup'
        self.formatted_data = f'-Xms{self.initial_memory}\n-Xmx{self.maximum_memory}\n' + \
                              '\n'.join(self._raw_extra_params)
        if backup_directory:
            utilities.backup_configuration_file(out_file_path, backup_directory,
                                                destination_file_prefix=backup_file_name)
        try:
            with open(out_file_path, 'w') as config_raw_f:
                config_raw_f.write(self.formatted_data)
            if utilities.is_root():
                utilities.set_ownership_of_file(out_file_path)
                utilities.set_permissions_of_file(out_file_path, 644)
        except IOError:
            raise exceptions.WriteConfigError('An error occurred while writing the configuration file to disk.')


class YamlConfigManager(GenericConfigManager):
    """
    A configuration manager for working with any YAML formatted configuration file
    """

    def __init__(self, config_data: Dict, name: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True,
                 **extract_tokens: Dict):
        """Work with YAML based configuration files

        Args:
            config_data: Configuration data dictionary
            name: The name of the configuration
            verbose: Include detailed debug messages
            stdout: Print output to console
            **extract_tokens: A dictionary object, where the keys represent the names of instance variables to create
            if the path to that variable exists. Paths are given using dot notation or as a Tuple.
        """
        super().__init__(config_data, name, verbose, stdout)
        if not utilities.is_setup():
            raise exceptions.DynamiteNotSetupError()
        self.config_data = config_data
        self.extract_tokens = extract_tokens
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.stdout = stdout
        self.verbose = verbose
        self.logger = get_logger(str(name), level=log_level, stdout=stdout)

    def parse_yaml_file(self) -> None:
        """
        Parse the yaml file.
        Returns:
            None
        """

        def set_instance_var_from_token(variable_name: str, data: Union[Dict, List]):
            """Given a variable name, and data; create an instance variable (at parse-time) of that name
            Args:
                variable_name: The name of the instance variable to update
                data: The parsed yaml object
            Returns:
                 True if successfully located
            """
            if variable_name not in self.extract_tokens.keys():
                return False
            key_path = self.extract_tokens[variable_name]
            value = data
            for k in key_path:
                if isinstance(value, dict):
                    try:
                        value = value[k]
                    except KeyError:
                        continue
                elif isinstance(value, list):
                    for list_entry in value:
                        if isinstance(list_entry, dict):
                            if k in list_entry.keys():
                                value = list_entry[k]
                else:
                    break
            setattr(self, var_name, value)
            return True

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None,
               top_text: Optional[str] = None) -> None:
        """Write out an updated configuration file, and optionally backup the old one.
        Args:
            out_file_path: The path to the output file; if none given overwrites existing
            backup_directory: The path to the backup directory
            top_text: The text to be appended at the top of the config file (typically used for YAML version header)
        Returns:
            None
        """
        out_file_name = os.path.basename(out_file_path)
        backup_file_name = out_file_name + '.backup'

        def update_dict_from_path(path, value) -> None:
            """Update the internal YAML dictionary object with the new values from our config
            Args:
                path: A tuple representing each level of a nested path in the yaml document ('vars', 'address-groups', 'HOME_NET') = /vars/address-groups/HOME_NET
                value: The new value
            Returns:
                 None
            """
            partial_config_data = self.config_data
            if len(path) > 1:
                for i in range(0, len(path) - 1):
                    k = path[i]
                    if isinstance(partial_config_data, dict):
                        partial_config_data = partial_config_data[k]
                    elif isinstance(partial_config_data, list):
                        for list_entry in partial_config_data:
                            if isinstance(list_entry, dict):
                                if k in list_entry.keys():
                                    partial_config_data = list_entry[k]
                    else:
                        break
            if value is None:
                return
            partial_config_data.update({path[-1]: value})

        # Backup old configuration first
        if backup_directory:
            utilities.backup_configuration_file(out_file_path, backup_directory,
                                                destination_file_prefix=backup_file_name)

        for k, v in vars(self).items():
            if k not in self.extract_tokens:
                continue
            token_path = self.extract_tokens[k]
            update_dict_from_path(token_path, v)
        try:
            with open(out_file_path, 'w') as config_yaml_f:
                if top_text:
                    config_yaml_f.write(f'{top_text}\n')
                try:
                    dump(self.config_data, config_yaml_f, default_flow_style=False, Dumper=NoAliasDumper)
                except RecursionError:
                    dump(self.config_data, config_yaml_f, default_flow_style=False)
            if utilities.is_root():
                utilities.set_ownership_of_file(out_file_path)
        except IOError:
            raise exceptions.WriteConfigError('An error occurred while writing the configuration file to disk.')
        self.logger.warning('Configuration updated. Restart this service to apply.')

    def get_printable_config(self, pretty_print: Optional[bool] = False) -> str:
        """
        Get the configuration as a dictionary object
        Args:
            pretty_print: Print the log entry in a nice tabular view
        Returns:
            A dictionary of config keys and values
        """
        reserved_keywords = ['logger', 'config_data', 'config_data_raw', 'extract_tokens']
        variables = {}
        for var in vars(self):
            if var.startswith('_'):
                continue
            elif var in reserved_keywords:
                continue
            variables[var] = getattr(self, var)
        if pretty_print:
            table = [['Config Option', 'Value']]
            table.extend([(label, value) for label, value in variables.items()])
            return tabulate(table, tablefmt='fancy_grid')
        return json.dumps(variables, indent=1)
