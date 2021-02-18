import os
import json
from typing import Callable, Dict, List, Optional, Union

from yaml import dump

from dynamite_nsm import utilities
from dynamite_nsm import exceptions as general_exceptions


class BackupConfigManager:

    def __init__(self, backup_directory: str):
        self.backup_directory = backup_directory

    def list_backup_configs(self) -> List:
        """
        List configuration backups

        :return: A list of dictionaries with the following keys: ["name", "path", "timestamp"]
        """
        return utilities.list_backup_configurations(self.backup_directory)

    def restore_backup_config(self, backup_name: str, restore_name: str):
        """
        Restore a configuration from our config store

        :param backup_name: The name of the configuration file or the keyword "recent" which will restore the most
        recent backup.
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

    def __init__(self, config_data: Dict):
        self.config_data = config_data
        self.formatted_data = json.dumps(config_data)

    def add_parser(self, parser: Callable, attribute_name):
        setattr(self, attribute_name, parser(self.config_data))

    def write_config(self, out_file_path: str, backup_directory: Optional[str] = None) -> None:
        # Backup old configuration first
        out_file_name = os.path.basename(out_file_path)
        backup_file_name = out_file_name + '.backup'
        if backup_directory:
            utilities.backup_configuration_file(out_file_path, backup_directory,
                                                destination_file_prefix=backup_file_name)
        try:
            with open(out_file_path, 'w') as config_raw_f:
                config_raw_f.write(self.formatted_data)
        except IOError:
            raise general_exceptions.WriteConfigError('An error occurred while writing the configuration file to disk.')
        utilities.set_permissions_of_file(out_file_path, 644)


class JavaOptionsConfigManager(GenericConfigManager):

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

    def __init__(self, config_data: Dict):
        super().__init__(config_data)

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

    def write_config(self, out_file_path: str, backup_directory: Optional[str] = None) -> None:
        # Backup old configuration first
        out_file_name = os.path.basename(out_file_path)
        backup_file_name = out_file_name + '.backup'
        self.formatted_data = f'-Xms={self.initial_memory}\n-Xmx={self.maximum_memory}\n' + \
            '\n'.join(self._raw_extra_params)
        if backup_directory:
            utilities.backup_configuration_file(out_file_path, backup_directory,
                                                destination_file_prefix=backup_file_name)
        try:
            with open(out_file_path, 'w') as config_raw_f:
                config_raw_f.write(self.formatted_data)
        except IOError:
            raise general_exceptions.WriteConfigError('An error occurred while writing the configuration file to disk.')
        utilities.set_permissions_of_file(out_file_path, 644)


class YamlConfigManager:

    def __init__(self, config_data: Dict, **extract_tokens: Dict):
        self.config_data = config_data
        self.extract_tokens = extract_tokens

    def parse_yaml_file(self) -> None:

        def set_instance_var_from_token(variable_name: str, data: Union[Dict, List]):
            """
            :param variable_name: The name of the instance variable to update
            :param data: The parsed yaml object
            :return: True if successfully located
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

    def write_config(self, out_file_path: str, backup_directory: Optional[str] = None,
                     top_text: Optional[str] = None) -> None:
        out_file_name = os.path.basename(out_file_path)
        backup_file_name = out_file_name + '.backup'

        def update_dict_from_path(path, value) -> None:
            """
            :param path: A tuple representing each level of a nested path in the yaml document
                        ('vars', 'address-groups', 'HOME_NET') = /vars/address-groups/HOME_NET
            :param value: The new value
            :return: None
            """
            partial_config_data = self.config_data
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
                dump(self.config_data, config_yaml_f, default_flow_style=False)
        except IOError:
            raise general_exceptions.WriteConfigError('An error occurred while writing the configuration file to disk.')
        utilities.set_permissions_of_file(out_file_path, 644)
