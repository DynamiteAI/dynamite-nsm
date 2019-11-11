import os
import sys
import tarfile
import subprocess

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from dynamite_nsm import const
from dynamite_nsm import utilities

INSTALL_DIRECTORY = '/opt/dynamite/oinkmaster/'


class OinkmasterInstaller:
    """
    An interface for installing OinkMaster Suricata update script
    """
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
        try:
            os.mkdir(self.install_directory)
        except Exception as e:
            if 'exists' not in str(e).lower():
                return False
        if stdout:
            sys.stdout.write('[+] Copying oinkmaster files.\n')
        try:
            utilities.copytree(os.path.join(const.INSTALL_CACHE, const.OINKMASTER_DIRECTORY_NAME),
                               self.install_directory)
        except Exception as e:
            sys.stderr.write('[-] Failed to copy {} -> {}: {}'.format(
                os.path.join(const.INSTALL_CACHE, const.OINKMASTER_DIRECTORY_NAME), self.install_directory, e))
            return False
        if 'OINKMASTER_HOME' not in open('/etc/dynamite/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Oinkmaster default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo OINKMASTER_HOME="{}" >> /etc/dynamite/environment'.format(self.install_directory),
                            shell=True)
        if stdout:
            sys.stdout.write('[+] Updating oinkmaster.conf with emerging-threats URL.\n')
        try:
            with open(os.path.join(self.install_directory, 'oinkmaster.conf'), 'a') as f:
                f.write('\nurl = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz')
        except Exception as e:
            sys.stderr.write('[-] Failed to update oinkmaster.conf: {}.\n'.format(e))
            return False
        return True


def update_suricata_rules():
    """
    Update Suricata rules specified in the oinkmaster.conf file

    :return: True if succeeded
    """
    environment_variables = utilities.get_environment_file_dict()
    suricata_config_directory = environment_variables.get('SURICATA_CONFIG')
    oinkmaster_install_directory = environment_variables.get('OINKMASTER_HOME')
    exit_code = subprocess.call('./oinkmaster.pl -C oinkmaster.conf -o {}'.format(
        os.path.join(suricata_config_directory, 'rules')), cwd=oinkmaster_install_directory, shell=True)
    sys.stdout.write('[+] Agent must be restarted for changes to take effect.\n')
    return exit_code == 0
