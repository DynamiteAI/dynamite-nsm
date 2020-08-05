import os
import sys
import shutil
import logging
import subprocess

from dynamite_nsm import const
from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.managerd import profile as managerd_profile
from dynamite_nsm.services.managerd import process as managerd_process
from dynamite_nsm.services.managerd import exceptions as managerd_exceptions


class InstallManager:

    def __init__(self, configuration_directory, install_directory, log_directory, stdout=True, verbose=False):

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('MANAGERD', level=log_level, stdout=stdout)

        self.install_directory = install_directory
        self.configuration_directory = configuration_directory
        self.log_directory = log_directory

        self.stdout = stdout
        self.verbose = verbose

    def setup_managerd(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info('Creating Managerd installation, configuration, and logging directories.')
        try:
            utilities.makedirs(os.path.join(self.install_directory, 'bin'), exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
            utilities.makedirs(os.path.join(self.log_directory, 'logs'), exist_ok=True)
        except Exception as e:
            self.logger.error('Failed to create required directory structure.')
            self.logger.debug("Failed to create required directory structure; {}".format(e))
            raise managerd_exceptions.InstallManagerDaemonError(
                "Failed to create required directory structure; {}".format(e))
        try:
            managerd_bin_path = os.path.join(const.DEFAULT_CONFIGS, 'managerd', 'managerd')
            shutil.copy(managerd_bin_path, os.path.join(self.install_directory, 'bin', 'managerd'))
        except Exception as e:
            self.logger.error('Failed to install managerd.')
            self.logger.debug("Failed to install managerd; {}".format(e))
            raise managerd_exceptions.InstallManagerDaemonError("Failed to install managerd; {}".format(e))
        try:
            managerd_config_path = os.path.join(const.DEFAULT_CONFIGS, 'managerd', 'config.yml')
            shutil.copy(managerd_config_path, os.path.join(self.configuration_directory, 'config.yml'))
        except Exception as e:
            self.logger.error('Failed to install managerd config.yml.')
            self.logger.debug("Failed to install managerd config.yml; {}".format(e))
            raise managerd_exceptions.InstallManagerDaemonError("Failed to install managerd config.yml; {}".format(e))

        try:
            sysctl = systemctl.SystemCtl()
        except general_exceptions.CallProcessError:
            raise managerd_exceptions.InstallManagerDaemonError("Could not find systemctl.")
        self.logger.info("Installing managerd systemd Service.")
        if not sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'managerd.service')):
            raise managerd_exceptions.InstallManagerDaemonError("Failed to install managerd systemd service.")

        try:
            with open(env_file) as env_f:
                env_f_text = env_f.read()
                if 'MANAGERD_INSTALL' not in env_f_text:
                    self.logger.info('Updating managerd default install path [{}]'.format(self.install_directory))
                    subprocess.call('echo MANAGERD_INSTALL="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
                if 'MANAGERD_CONFIG' not in env_f_text:
                    self.logger.info('Updating managerd default config path [{}]'.format(self.configuration_directory))
                    subprocess.call('echo MANAGERD_CONFIG="{}" >> {}'.format(self.configuration_directory, env_file),
                                    shell=True)
                if 'MANAGERD_LOGS' not in env_f_text:
                    self.logger.info('Updating managerd default log path [{}]'.format(self.log_directory))
                    subprocess.call('echo MANAGERD_LOGS="{}" >> {}'.format(self.log_directory, env_file),
                                    shell=True)
        except Exception as e:
            self.logger.error("General error occurred while attempting to install managerd.")
            self.logger.debug("General error occurred while attempting to install managerd; {}".format(e))
            raise managerd_exceptions.InstallManagerDaemonError(
                "General error occurred while attempting to install FileBeat; {}".format(e))


def install_managerd(configuration_directory, install_directory, log_directory, stdout=True, verbose=False):
    """
    Install Manager Daemon

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/managerd)
    :param install_directory: Path to the install directory (E.G /opt/dynamite/managerd/)
    :param log_directory: Path to the log directory (E.G /var/log/dynamite/managerd/)
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('MANAGERD', level=log_level, stdout=stdout)
    managerd_profiler = managerd_profile.ProcessProfiler()
    if managerd_profiler.is_installed():
        logger.error('managerd is already installed. If you wish to re-install, first uninstall.')
        raise managerd_exceptions.AlreadyInstalledManagerDaemonError()
    managerd_installer = InstallManager(configuration_directory, install_directory, log_directory, stdout=stdout,
                                        verbose=verbose)
    managerd_installer.setup_managerd()


def uninstall_managerd(prompt_user=True, stdout=True, verbose=False):
    """
    Uninstall managerd

    :param prompt_user: Print a warning before continuing
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('MANAGERD', level=log_level, stdout=stdout)

    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    managerd_profiler = managerd_profile.ProcessProfiler()
    if not managerd_profiler.is_installed():
        raise managerd_exceptions.UninstallManagerDaemonError("managerd is not installed.")
    if prompt_user:
        sys.stderr.write(
            '\n\033[93m[-] WARNING! Removing managerd will disable various performance metric gathering from occurring.'
            '\033[0m\n')
        resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\n\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    if managerd_profiler.is_running():
        managerd_process.ProcessManager().stop()
    try:
        shutil.rmtree(environment_variables['MANAGERD_LOGS'])
        shutil.rmtree(environment_variables['MANAGERD_INSTALL'])
        shutil.rmtree(environment_variables['MANAGERD_CONFIG'])
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        env_lines = ''
        with open(env_file) as env_fr:
            for line in env_fr.readlines():
                if 'MANAGERD_LOGS' in line:
                    continue
                elif 'MANAGERD_INSTALL' in line:
                    continue
                elif 'MANAGERD_CONFIG' in line:
                    continue
                elif line.strip() == '':
                    continue
                env_lines += line.strip() + '\n'
        with open(env_file, 'w') as env_fw:
            env_fw.write(env_lines)
    except Exception as e:
        logger.error("General error occurred while attempting to uninstall managerd.".format(e))
        logger.debug("General error occurred while attempting to uninstall managerd; {}".format(e))
        raise managerd_exceptions.UninstallManagerDaemonError(
            "General error occurred while attempting to uninstall kibana; {}".format(e))
    try:
        sysctl = systemctl.SystemCtl()
    except general_exceptions.CallProcessError:
        raise managerd_exceptions.UninstallManagerDaemonError("Could not find systemctl.")
    sysctl.uninstall_and_disable('manaagerd')
