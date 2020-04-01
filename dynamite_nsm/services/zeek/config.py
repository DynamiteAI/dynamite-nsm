import os
import time
import shutil
import subprocess

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from dynamite_nsm import utilities


class ScriptConfigManager:
    """
    Wrapper for configuring broctl sites/local.bro
    """
    def __init__(self, configuration_directory):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
        """
        self.configuration_directory = configuration_directory
        self.zeek_scripts = {}
        self.zeek_sigs = {}
        self.zeek_redefs = {}

        self._parse_zeek_scripts()

    def _parse_zeek_scripts(self):
        """
        Parse the local.bro configuration file, and determine which scripts are enabled/disabled
        """
        for line in open(os.path.join(self.configuration_directory, 'site', 'local.bro')).readlines():
            line = line.replace(' ', '').strip()
            if '@load-sigs' in line:
                if line.startswith('#'):
                    enabled = False
                    line = line[1:]
                else:
                    enabled = True
                sigs = line.split('@load-sigs')[1]
                self.zeek_sigs[sigs] = enabled
            elif '@load' in line:
                if line.startswith('#'):
                    enabled = False
                    line = line[1:]
                else:
                    enabled = True
                script = line.split('@load')[1]
                self.zeek_scripts[script] = enabled
            elif line.startswith('redef'):
                definition, value = line.split('redef')[1].split('=')
                self.zeek_redefs[definition] = value

    def disable_script(self, name):
        """
        :param name: The name of the script (E.G protocols/http/software)
        :return: True, if the script was successfully disabled
        """
        try:
            self.zeek_scripts[name] = False
            return True
        except KeyError:
            return False

    def enable_script(self, name):
        """
        :param name: The name of the script (E.G protocols/http/software)
        :return: True, if the script was successfully enabled
        """
        try:
            self.zeek_scripts[name] = True
            return True
        except KeyError:
            return False

    def list_disabled_scripts(self):
        """
        :return: A list of disabled Zeek scripts
        """
        return [script for script in self.zeek_scripts.keys() if not self.zeek_scripts[script]]

    def list_enabled_scripts(self):
        """
        :return: A list of enabled Zeek scripts
        """
        return [script for script in self.zeek_scripts.keys() if self.zeek_scripts[script]]

    def list_enabled_sigs(self):
        """
        :return: A list of enabled Zeek signatures
        """
        return [sig for sig in self.zeek_sigs.keys() if self.zeek_sigs[sig]]

    def list_disabled_sigs(self):
        """
        :return: A list of disabled Zeek signatures
        """
        return [sig for sig in self.zeek_sigs.keys() if not self.zeek_sigs[sig]]

    def list_redefinitions(self):
        return [(redef, val) for redef, val in self.zeek_redefs.items()]

    def write_config(self):
        """
        Overwrite the existing local.bro config with changed values
        """
        timestamp = int(time.time())
        output_str = ''
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        zeek_config_backup = os.path.join(backup_configurations, 'local.bro.backup.{}'.format(timestamp))

        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        for e_script in self.list_enabled_scripts():
            output_str += '@load {}\n'.format(e_script)
        for d_script in self.list_disabled_scripts():
            output_str += '#@load {}\n'.format(d_script)
        for e_sig in self.list_enabled_sigs():
            output_str += '@load-sigs {}\n'.format(e_sig)
        for d_sig in self.list_disabled_sigs():
            output_str += '@load-sigs {}\n'.format(d_sig)
        for rdef, val in self.list_redefinitions():
            output_str += 'redef {} = {}\n'.format(rdef, val)
        shutil.move(os.path.join(self.configuration_directory, 'site', 'local.bro'), zeek_config_backup)
        with open(os.path.join(self.configuration_directory, 'site', 'local.bro'), 'w') as f:
            f.write(output_str)


class NodeConfigManager:
    """
    Wrapper for configuring broctl node.cfg
    """
    def __init__(self, install_directory):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        """
        self.install_directory = install_directory
        self.node_config = self._parse_node_config()

    def _parse_node_config(self):
        """
        :return: A dictionary representing the configurations storred within node.cfg
        """
        node_config = {}
        config_parser = ConfigParser()
        config_parser.readfp(open(os.path.join(self.install_directory, 'etc', 'node.cfg')))
        for section in config_parser.sections():
            node_config[section] = {}
            for item in config_parser.items(section):
                key, value = item
                node_config[section][key] = value
        return node_config

    def add_logger(self, name, host):
        """
        :param name: The name of the logger
        :param host: The host on which the logger is running
        :return: True, if added successfully
        """
        self.node_config[name] = {
            'type': 'logger',
            'host': host
        }
        return True

    def add_manager(self, name, host):
        """
        :param name: The name of the manager
        :param host: The host on which the manager is running
        :return: True, if added successfully
        """
        self.node_config[name] = {
            'type': 'manager',
            'host': host
        }
        return True

    def add_proxy(self, name, host):
        """
        :param name: The name of the proxy
        :param host: The host on which the proxy is running
        :return: True, if added successfully
        """
        self.node_config[name] = {
            'type': 'proxy',
            'host': host
        }
        return True

    def add_worker(self, name, interface, host, lb_procs=10, pin_cpus=(0, 1)):
        """
        :param name: The name of the worker
        :param interface: The interface that the worker should be monitoring
        :param host: The host on which the worker is running
        :param lb_procs: The number of Zeek processes associated with a given worker
        :param pin_cpus: Core affinity for the processes (iterable)
        :return: True, if added successfully
        """
        if max(pin_cpus) < utilities.get_cpu_core_count() and min(pin_cpus) >= 0:
            pin_cpus = [str(cpu_n) for cpu_n in pin_cpus]
            self.node_config[name] = {
                'type': 'worker',
                'interface': interface,
                'lb_method': 'pf_ring',
                'lb_procs': lb_procs,
                'pin_cpus': ','.join(pin_cpus),
                'host': host
            }
            return True
        return False

    def remove_logger(self, name):
        """
        :param name: The name of the logger
        :return: True, if successfully removed
        """
        try:
            if self.node_config[name]['type'] == 'logger':
                del self.node_config[name]
            else:
                return False
        except KeyError:
            return False

    def remove_manager(self, name):
        """
        :param name: The name of the manager
        :return: True, if successfully removed
        """
        try:
            if self.node_config[name]['type'] == 'manager':
                del self.node_config[name]
            else:
                return False
        except KeyError:
            return False

    def remove_proxy(self, name):
        """
        :param name: The name of the proxy
        :return: True, if successfully removed
        """
        try:
            if self.node_config[name]['type'] == 'proxy':
                del self.node_config[name]
            else:
                return False
        except KeyError:
            return False

    def remove_worker(self, name):
        """
        :param name: The name of the worker
        :return: True, if successfully removed
        """
        try:
            if self.node_config[name]['type'] == 'worker':
                del self.node_config[name]
            else:
                return False
        except KeyError:
            return False
        return True

    def list_workers(self):
        """
        :return: A list of worker names
        """
        workers = []
        for component, values in self.node_config.items():
            if values['type'] == 'worker':
                workers.append(component)
        return workers

    def list_proxies(self):
        """
        :return: A list of proxy names
        """
        proxies = []
        for component, values in self.node_config.items():
            if values['type'] == 'proxy':
                proxies.append(component)
        return proxies

    def list_loggers(self):
        """
        :return: A list of logger names
        """
        loggers = []
        for component, values in self.node_config.items():
            if values['type'] == 'logger':
                loggers.append(component)
        return loggers

    def get_manager(self):
        """
        :return: The name of the manager
        """
        for component, values in self.node_config.items():
            if values['type'] == 'manager':
                return component
        return None

    def write_config(self):
        """
        Overwrite the existing node.cfg with changed values
        """
        config = ConfigParser()
        for section in self.node_config.keys():
            for k, v in self.node_config[section].items():
                try:
                    config.add_section(section)
                except Exception: # Duplicate section
                    pass
                config.set(section, k, str(v))
                with open(os.path.join(self.install_directory, 'etc', 'node.cfg'), 'w') as configfile:
                    config.write(configfile)
