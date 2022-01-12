import os
import shutil

from dynamite_nsm import const
from dynamite_nsm import logger
from dynamite_nsm import utilities
from dynamite_nsm import exceptions
from dynamite_nsm.services.updates import install as update_installer

sudoers_patch = """
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status kibana*
"""


def get_sudoers_directory_path():
    with open(const.SUDOERS_FILE, 'r') as sudoers_in:
        for i, line in enumerate(sudoers_in.readlines()):
            line = line.strip()
            if line.startswith('#includedir'):
                include_directory = ' '.join(line.split(' ')[1:])
                break
    return include_directory


class InstallManager:

    def __init__(self):
        """
        Prepare this environment for DynamiteNSM
        """
        if not utilities.is_root():
            raise PermissionError('You must be root to setup DynamiteNSM.')
        self.logger = logger.get_logger('setup.install', stdout=True, stdout_only=True)

    @staticmethod
    def patch_sudoers():
        include_directory = get_sudoers_directory_path()
        if not include_directory:
            include_directory = const.SUDOERS_DIRECTORY
            utilities.makedirs(include_directory)
            with open(const.SUDOERS_FILE, 'a') as sudoers_out:
                sudoers_out.write(f'\n#includedir {include_directory}')
        with open(f'{include_directory}/dynamite', 'w') as dynamite_sudoers_out:
            dynamite_sudoers_out.write(sudoers_patch)

    def setup(self):
        fresh_install_paths = [const.LOG_PATH, const.CONFIG_PATH, const.INSTALL_PATH, const.INSTALL_CACHE]
        try:
            self.logger.info('Creating dynamite user and group.')
            utilities.create_dynamite_user()
            for path in fresh_install_paths:
                self.logger.info(f'Reserving {path}.')
                utilities.makedirs(path)
                utilities.set_ownership_of_file(path, user='dynamite', group='dynamite')
                utilities.set_permissions_of_file(path, 770)
            self.logger.info('Creating Dynamite NSM Environment file.')
            utilities.create_dynamite_environment_file()
            self.logger.info('Patching sudoers file.')
            self.patch_sudoers()
            self.logger.info('Checking for updates')
            update_installer.InstallManager(stdout=True, verbose=True).setup()
            self.logger.info('Setup complete. You can now install and manage services.')
        except Exception:
            raise exceptions.InstallError('Failed to setup DynamiteNSM directory structure.')


class UninstallManager:

    def __init__(self):
        """
        Completely remove DynamiteNSM from this environment
        """
        if not utilities.is_root():
            raise PermissionError('You must be root to uninstall DynamiteNSM.')
        self.logger = logger.get_logger('setup.install', stdout=True, stdout_only=True)

    def uninstall(self):
        from dynamite_nsm.services.zeek import profile as zeek_profile
        from dynamite_nsm.services.suricata import profile as suricata_profile
        from dynamite_nsm.services.filebeat import profile as filebeat_profile
        from dynamite_nsm.services.elasticsearch import profile as elasticsearch_profile
        from dynamite_nsm.services.kibana import profile as kibana_profile
        from dynamite_nsm.services.logstash import profile as logstash_profile
        from dynamite_nsm.services.zeek import process as zeek_process
        from dynamite_nsm.services.suricata import process as suricata_process
        from dynamite_nsm.services.filebeat import process as filebeat_process
        from dynamite_nsm.services.elasticsearch import process as elasticsearch_process
        from dynamite_nsm.services.kibana import process as kibana_process
        from dynamite_nsm.services.logstash import process as logstash_process
        from dynamite_nsm.services.zeek import install as zeek_install
        from dynamite_nsm.services.suricata import install as suricata_install
        from dynamite_nsm.services.filebeat import install as filebeat_install
        from dynamite_nsm.services.elasticsearch import install as elasticsearch_install
        from dynamite_nsm.services.kibana import install as kibana_install
        from dynamite_nsm.services.logstash import install as logstash_install
        profilers = [zeek_profile.ProcessProfiler, suricata_profile.ProcessProfiler, filebeat_profile.ProcessProfiler,
                     elasticsearch_profile.ProcessProfiler, kibana_profile.ProcessProfiler,
                     logstash_profile.ProcessProfiler]
        processes = [zeek_process.ProcessManager, suricata_process.ProcessManager, filebeat_process.ProcessManager,
                     elasticsearch_process.ProcessManager, kibana_process.ProcessManager,
                     logstash_process.ProcessManager]
        uninstallers = [zeek_install.UninstallManager, suricata_install.UninstallManager,
                        filebeat_install.UninstallManager,
                        elasticsearch_install.UninstallManager, kibana_install.UninstallManager,
                        logstash_install.UninstallManager]
        try:
            for i, Profiler in enumerate(profilers):
                if Profiler().is_installed():
                    self.logger.info(f'Found {processes[i]().name}. Safely uninstalling.')
                    processes[i]().stop()
                    uninstallers[i]().uninstall()
            self.logger.info('Removing patched sudoers file.')
            utilities.safely_remove_file(f'{get_sudoers_directory_path()}/dynamite')
            for directory in [const.LOG_PATH, const.CONFIG_PATH, const.INSTALL_PATH, const.INSTALL_PATH]:
                self.logger.info(f'Removing {directory}.')
                if os.path.exists(directory):
                    shutil.rmtree(directory)
        except Exception:
            raise exceptions.UninstallError('Failed to remove DynamiteNSM from this system.')

