import os
from typing import Dict, List, Optional

from yaml import dump
from dynamite_nsm import utilities


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


class YamlConfigManager:

    def __init__(self, config_data: Dict, **extract_tokens: Dict):
        self.config_data = config_data
        self.extract_tokens = extract_tokens

    def parse_yaml_file(self) -> None:

        def set_instance_var_from_token(variable_name, data):
            """
            :param variable_name: The name of the instance variable to update
            :param data: The parsed yaml object
            :return: True if successfully located
            """
            if variable_name not in self.extract_tokens.keys():
                return False
            key_path = self.extract_tokens[variable_name]
            value = data
            try:
                for k in key_path:
                    value = value[k]
                setattr(self, var_name, value)
            except KeyError:
                pass
            return True

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def write_config(self, out_file_path: str, backup_directory: Optional[str] = None) -> None:
        out_file_name = os.path.basename(out_file_path)
        backup_file_name = out_file_name + '.backup'

        def update_dict_from_path(path, value):
            """
            :param path: A tuple representing each level of a nested path in the yaml document
                        ('vars', 'address-groups', 'HOME_NET') = /vars/address-groups/HOME_NET
            :param value: The new value
            :return: None
            """
            partial_config_data = self.config_data
            for i in range(0, len(path) - 1):
                try:
                    partial_config_data = partial_config_data[path[i]]
                except KeyError:
                    pass
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
        with open(out_file_path, 'w') as configyaml:
            dump(self.config_data, configyaml, default_flow_style=False)
            utilities.set_permissions_of_file(out_file_path, 744)
