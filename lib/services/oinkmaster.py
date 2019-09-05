import os
import sys
import shutil
import tarfile
import subprocess

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from lib import const
from lib import utilities

INSTALL_DIRECTORY = '/opt/dynamite/oinkmaster/'


class OinkmasterInstaller:
    def __init__(self, install_directory=INSTALL_DIRECTORY):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/oinkmaster/)
        """
        self.install_directory = install_directory

    @staticmethod
    def download_oinkmaster(stdout=False):
        """
        Download Oinkmaster archive

        :param stdout: Print output to console
        """
        for url in open(const.OINKMASTER_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.OINKMASTER_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_oinkmaster(stdout=False):
        """
        Extract Oinkmaster to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.OINKMASTER_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.OINKMASTER_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_oinkmaster(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Copying oinkmaster files.\n')
        try:
            utilities.copytree(os.path.join(const.INSTALL_CACHE, const.OINKMASTER_DIRECTORY_NAME), self.install_directory)
        except Exception as e:
            sys.stderr.write('[-] Failed to copy {} -> {}: {}'.format(
                os.path.join(const.INSTALL_CACHE, const.OINKMASTER_DIRECTORY_NAME), self.install_directory, e))


def update_suricata_rules(suricata_config_directory, oinkmaster_install_directory=INSTALL_DIRECTORY):
    subprocess.call('./oinkmaster.pl -C oinkmaster.conf -o {}'.format(suricata_config_directory),
                    cwd=oinkmaster_install_directory, shell=True)