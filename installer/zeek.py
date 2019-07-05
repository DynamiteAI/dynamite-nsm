import os
import sys
import time
import tarfile
import subprocess

from installer import const
from installer import pf_ring
from installer import utilities
from installer import package_manager


CONFIGURATION_DIRECTORY = '/etc/dynamite/zeek/'
INSTALL_DIRECTORY = '/opt/dynamite/zeek/'


class ZeekInstaller:

    def __init__(self,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 install_directory=INSTALL_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        """

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory

    @staticmethod
    def download_zeek(stdout=False):
        """
        Download Zeek archive

        :param stdout: Print output to console
        """
        for url in open(const.ZEEK_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.ZEEK_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_zeek(stdout=False):
        """
        Extract Zeek to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.ZEEK_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.ZEEK_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    @staticmethod
    def install_dependencies():
        pkt_mng = package_manager.OSPackageManager()
        if not pkt_mng.refresh_package_indexes():
            return False
        packages = None
        if pkt_mng.package_manager == 'apt-get':
            packages = ['cmake', 'make', 'gcc', 'g++', 'flex', 'bison', 'libpcap-dev', 'libssl-dev',
                        'python-dev', 'swig', 'zlib1g-dev']
        elif pkt_mng.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libpcap-devel', 'openssl-devel',
                        'python-devel', 'swig', 'zlib-devel']
        if packages:
            return pkt_mng.install_packages(packages)
        return False

    def setup_zeek(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating zeek install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        if stdout:
            sys.stdout.write('[+] Installing PF_RING kernel modules and dependencies.\n')
            sys.stdout.flush()
            time.sleep(1)
        pf_ring_install = pf_ring.PFRingInstaller()
        pf_ring_install.download_pf_ring(stdout=True)
        pf_ring_install.extract_pf_ring(stdout=True)
        pf_ring_install.setup_pf_ring(stdout=True)
        if stdout:
            sys.stdout.write('[+] Compiling Zeek from source. This can take up to 30 minutes. Have a cup of coffee.')
            sys.stdout.flush()
            time.sleep(5)
        subprocess.call('./configure --prefix={} --scriptdir={} --with-pcap={}'.format(
            self.install_directory, self.configuration_directory, pf_ring_install.install_directory),
            shell=True, cwd=os.path.join(const.INSTALL_CACHE, 'bro-2.6.2'))
        subprocess.call('make; make install', shell=True, cwd=os.path.join(const.INSTALL_CACHE, 'bro-2.6.2'))
        if 'ZEEK_HOME' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Zeek default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo ZEEK_HOME="{}" >> /etc/environment'.format(self.install_directory),
                            shell=True)
        if 'ZEEK_SCRIPTS' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Zeek default script path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo ZEEK_SCRIPTS="{}" >> /etc/environment'.format(self.configuration_directory),
                            shell=True)
