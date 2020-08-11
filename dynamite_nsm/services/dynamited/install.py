import os
import sys
import shutil
import logging
import subprocess

from dynamite_nsm import const
from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.base import install
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.dynamited import profile as dynamited_profile
from dynamite_nsm.services.dynamited import process as dynamited_process
from dynamite_nsm.services.dynamited import exceptions as dynamited_exceptions


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory, install_directory, log_directory, download_dynamited_archive=True,
                 stdout=True, verbose=False):

        self.install_directory = install_directory
        self.configuration_directory = configuration_directory
        self.log_directory = log_directory

        self.stdout = stdout
        self.verbose = verbose
        install.BaseInstallManager.__init__(self, 'dynamited', verbose=self.verbose, stdout=stdout)
        if download_dynamited_archive:
            try:
                self.logger.info("Attempting to download Manager Daemon archive.")
                self.download_from_mirror(const.DYNAMITED_MIRRORS, const.DYNAMITED_ARCHIVE_NAME, stdout=stdout,
                                          verbose=verbose)
            except general_exceptions.DownloadError as e:
                self.logger.error("Failed to download dynamited archive.")
                self.logger.debug("Failed to download dynamited archive, threw: {}.".format(e))
                raise dynamited_exceptions.InstallDynamiteDaemonError("Failed to download dynamited archive.")
        try:
            self.logger.info("Attempting to extract dynamited archive ({}).".format(const.DYNAMITED_ARCHIVE_NAME))
            self.extract_archive(os.path.join(const.INSTALL_CACHE, const.DYNAMITED_ARCHIVE_NAME))
            self.logger.info("Extraction completed.")
        except general_exceptions.ArchiveExtractionError as e:
            self.logger.error("Failed to extract dynamited archive.")
            self.logger.debug("Failed to extract dynamited archive, threw: {}.".format(e))
            raise dynamited_exceptions.InstallDynamiteDaemonError("Failed to extract dynamited archive")

    def setup_dynamited(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info('Creating dynamited installation, configuration, and logging directories.')
        try:
            utilities.makedirs(os.path.join(self.install_directory, 'bin'), exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
            utilities.makedirs(os.path.join(self.log_directory, 'logs'), exist_ok=True)
        except Exception as e:
            self.logger.error('Failed to create required directory structure.')
            self.logger.debug("Failed to create required directory structure; {}".format(e))
            raise dynamited_exceptions.InstallDynamiteDaemonError(
                "Failed to create required directory structure; {}".format(e))
        try:
            dynamited_bin_path = os.path.join(const.INSTALL_CACHE, 'dynamited')
            shutil.copy(dynamited_bin_path, os.path.join(self.install_directory, 'bin', 'dynamited'))
        except Exception as e:
            self.logger.error('Failed to install dynamited.')
            self.logger.debug("Failed to install dynamited; {}".format(e))
            raise dynamited_exceptions.InstallDynamiteDaemonError("Failed to install dynamited; {}".format(e))
        try:
            dynamited_config_path = os.path.join(const.DEFAULT_CONFIGS, 'dynamited', 'config.yml')
            shutil.copy(dynamited_config_path, os.path.join(self.configuration_directory, 'config.yml'))
        except Exception as e:
            self.logger.error('Failed to install dynamited config.yml.')
            self.logger.debug("Failed to install dynamited config.yml; {}".format(e))
            raise dynamited_exceptions.InstallDynamiteDaemonError(
                "Failed to install dynamited config.yml; {}".format(e))

        try:
            sysctl = systemctl.SystemCtl()
        except general_exceptions.CallProcessError:
            raise dynamited_exceptions.InstallDynamiteDaemonError("Could not find systemctl.")
        self.logger.info("Installing dynamited systemd Service.")
        if not sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'dynamited.service')):
            raise dynamited_exceptions.InstallDynamiteDaemonError("Failed to install dynamited systemd service.")

        try:
            with open(env_file) as env_f:
                env_f_text = env_f.read()
                if 'DYNAMITED_INSTALL' not in env_f_text:
                    self.logger.info('Updating dynamited default install path [{}]'.format(self.install_directory))
                    subprocess.call('echo DYNAMITED_INSTALL="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
                if 'DYNAMITED_CONFIG' not in env_f_text:
                    self.logger.info('Updating dynamited default config path [{}]'.format(self.configuration_directory))
                    subprocess.call('echo DYNAMITED_CONFIG="{}" >> {}'.format(self.configuration_directory, env_file),
                                    shell=True)
                if 'DYNAMITED_LOGS' not in env_f_text:
                    self.logger.info('Updating dynamited default log path [{}]'.format(self.log_directory))
                    subprocess.call('echo DYNAMITED_LOGS="{}" >> {}'.format(self.log_directory, env_file),
                                    shell=True)
        except Exception as e:
            self.logger.error("General error occurred while attempting to install dynamited.")
            self.logger.debug("General error occurred while attempting to install dynamited; {}".format(e))
            raise dynamited_exceptions.InstallDynamiteDaemonError(
                "General error occurred while attempting to install FileBeat; {}".format(e))


def install_dynamited(configuration_directory, install_directory, log_directory, stdout=True, verbose=False):
    """
    Install Manager Daemon

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/dynamited)
    :param install_directory: Path to the install directory (E.G /opt/dynamite/dynamited/)
    :param log_directory: Path to the log directory (E.G /var/log/dynamite/dynamited/)
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('DYNAMITED', level=log_level, stdout=stdout)
    dynamited_profiler = dynamited_profile.ProcessProfiler()
    if dynamited_profiler.is_installed():
        logger.error('dynamited is already installed. If you wish to re-install, first uninstall.')
        raise dynamited_exceptions.AlreadyInstalledDynamiteDaemonError()
    dynamited_installer = InstallManager(configuration_directory, install_directory, log_directory, stdout=stdout,
                                         verbose=verbose)
    dynamited_installer.setup_dynamited()


def uninstall_dynamited(prompt_user=True, stdout=True, verbose=False):
    """
    Uninstall dynamited

    :param prompt_user: Print a warning before continuing
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('DYNAMITED', level=log_level, stdout=stdout)

    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    dynamited_profiler = dynamited_profile.ProcessProfiler()
    if not dynamited_profiler.is_installed():
        raise dynamited_exceptions.UninstallDynamiteDaemonError("dynamited is not installed.")
    if prompt_user:
        sys.stderr.write(
            '\n\033[93m[-] WARNING! Removing dynamited will disable various performance metric gathering from '
            'occurring.\033[0m\n')
        resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\n\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    if dynamited_profiler.is_running():
        dynamited_process.ProcessManager().stop()
    try:
        shutil.rmtree(environment_variables['DYNAMITED_LOGS'])
        shutil.rmtree(environment_variables['DYNAMITED_INSTALL'])
        shutil.rmtree(environment_variables['DYNAMITED_CONFIG'])
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        env_lines = ''
        with open(env_file) as env_fr:
            for line in env_fr.readlines():
                if 'DYNAMITED_LOGS' in line:
                    continue
                elif 'DYNAMITED_INSTALL' in line:
                    continue
                elif 'DYNAMITED_CONFIG' in line:
                    continue
                elif line.strip() == '':
                    continue
                env_lines += line.strip() + '\n'
        with open(env_file, 'w') as env_fw:
            env_fw.write(env_lines)
    except Exception as e:
        logger.error("General error occurred while attempting to uninstall dynamited.".format(e))
        logger.debug("General error occurred while attempting to uninstall dynamited; {}".format(e))
        raise dynamited_exceptions.UninstallDynamiteDaemonError(
            "General error occurred while attempting to uninstall dynamited; {}".format(e))
    try:
        sysctl = systemctl.SystemCtl()
    except general_exceptions.CallProcessError:
        raise dynamited_exceptions.UninstallDynamiteDaemonError("Could not find systemctl.")
    sysctl.uninstall_and_disable('dynamited')
