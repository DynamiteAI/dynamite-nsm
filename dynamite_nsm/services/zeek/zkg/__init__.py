import os
import logging
import subprocess
from typing import Optional

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger


class InstallZeekPackageError(Exception):

    def __init__(self, message):
        """
        Thrown when a Zeek package fail to install

        Args:
            message: A more specific error message
        """
        msg = "An error occurred while installing a Zeek package: {}".format(message)
        super(InstallZeekPackageError, self).__init__(msg)


def install_zeek_package(package_git_url: str, stdout: Optional[bool] = True, verbose: Optional[bool] = False):
    """Install a Zeek package via ZKG

    Args:
        package_git_url: The path to the git repo containing the Zeek package
        stdout: Print the output to console
        verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('zeek.zkg.package_install', level=log_level, stdout=stdout)
    environment_variables = utilities.get_environment_file_dict()
    zeek_install_dir = environment_variables.get('ZEEK_HOME')
    logger.info(f'Installing Zeek package: {package_git_url}.')
    if not zeek_install_dir:
        logger.error("Could not resolve ZEEK_HOME environment_variable. Is Zeek installed?")
        raise InstallZeekPackageError('Could not resolve ZEEK_HOME environment_variable. Is ZKG installed? ')
    zkg_binary_dir = f'{zeek_install_dir}/bin'
    zkg_install_p = subprocess.Popen(f'./zkg install {package_git_url} --force',
                                     cwd=zkg_binary_dir, shell=True, stderr=subprocess.PIPE)
    err = zkg_install_p.communicate()
    if zkg_install_p.returncode != 0:
        logger.error(f'ZKG returned a non-zero exit-code: {zkg_install_p.returncode}.')
        raise InstallZeekPackageError(
            f'ZKG returned a non-zero exit-code during install: {zkg_install_p.returncode}; err: {err}.')
    zkg_load_p = subprocess.Popen(f'./zkg load {package_git_url}',
                                  cwd=zkg_binary_dir, shell=True, stderr=subprocess.PIPE)
    err = zkg_load_p.communicate()
    if zkg_load_p.returncode != 0:
        logger.error(f'ZKG returned a non-zero exit-code during load: {zkg_load_p.returncode}.')
        raise InstallZeekPackageError(
            f'ZKG returned a non-zero exit-code during load: {zkg_load_p.returncode}; err: {err}.')


if __name__ == '__main__':
    install_zeek_package('https://github.com/corelight/cve-2021-44228.git', stdout=True, verbose=True)