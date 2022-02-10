import os
import shutil

from dynamite_nsm import const
from dynamite_nsm import logger
from dynamite_nsm import utilities
from dynamite_nsm import exceptions
from dynamite_nsm.services.updates import install as update_installer

systemctl_bin_path = shutil.which('systemctl')
setcap_bin_path = shutil.which('setcap')

sudoers_patch = f"""
%dynamite ALL=(root) NOPASSWD: {setcap_bin_path} *
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} enable zeek*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} disable zeek*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} is-enabled zeek*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} show zeek*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} stop zeek*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} start zeek*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} restart zeek*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} status zeek*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} enable suricata*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} disable suricata*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} is-enabled suricata*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} show suricata*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} stop suricata*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} start suricata*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} restart suricata*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} status suricata*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} enable filebeat*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} disable filebeat*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} is-enabled filebeat*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} show filebeat*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} stop filebeat*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} start filebeat*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} restart filebeat*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} status filebeat*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} enable elasticsearch*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} disable elasticsearch*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} is-enabled elasticsearch*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} show elasticsearch*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} stop elasticsearch*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} start elasticsearch*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} restart elasticsearch*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} status elasticsearch*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} enable logstash*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} disable logstash*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} is-enabled logstash*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} show logstash*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} stop logstash*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} start logstash*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} restart logstash*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} status logstash*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} enable kibana*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} disable kibana*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} is-enabled kibana*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} show kibana*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} stop kibana*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} start kibana*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} restart kibana*
%dynamite ALL=(root) NOPASSWD: {systemctl_bin_path} status kibana*
"""


class InstallManager:

    def __init__(self):
        """
        Prepare this environment for DynamiteNSM
        """
        if not utilities.is_root():
            raise exceptions.RequiresRootError()
        self.logger = logger.get_logger('setup.install', stdout=True, stdout_only=True)

    @staticmethod
    def patch_sudoers():
        include_directory = utilities.get_sudoers_directory_path()
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
            raise exceptions.RequiresRootError()
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
            utilities.safely_remove_file(f'{utilities.get_sudoers_directory_path()}/dynamite')
            for directory in [const.LOG_PATH, const.CONFIG_PATH, const.INSTALL_PATH, const.INSTALL_PATH]:
                self.logger.info(f'Removing {directory}.')
                if os.path.exists(directory):
                    shutil.rmtree(directory)
        except Exception:
            raise exceptions.UninstallError('Failed to remove DynamiteNSM from this system.')


