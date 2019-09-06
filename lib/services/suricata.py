import os
import sys
import time
import shutil
import tarfile
import subprocess

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from lib import const
from lib import utilities
from lib import package_manager
from lib.services import pf_ring
from lib.services import oinkmaster


INSTALL_DIRECTORY = '/opt/dynamite/suricata/'
CONFIGURATION_DIRECTORY = '/etc/dynamite/suricata'


class SuricataInstaller:

    def __init__(self,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 install_directory=INSTALL_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/suricata/)
        """

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory

    @staticmethod
    def download_suricata(stdout=False):
        """
        Download Suricata archive

        :param stdout: Print output to console
        """
        for url in open(const.SURICATA_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.SURICATA_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_suricata(stdout=False):
        """
        Extract Suricata to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.SURICATA_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.SURICATA_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    @staticmethod
    def install_dependencies():
        pacman = package_manager.OSPackageManager()
        if not pacman.refresh_package_indexes():
            return False
        packages = None
        if pacman.package_manager == 'apt-get':
            packages = ['cmake', 'make', 'gcc', 'g++', 'libtool', 'automake', 'pkg-config', 'libpcre3-dev',
                        'libyaml-dev','libjansson-dev', 'rustc', 'cargo', 'python-pip']
        elif pacman.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'libtool', 'automake', 'pkgconfig', 'pcre-devel',
                        'libyaml-devel', 'jansson-devel', 'rustc', 'cargo', 'python-pip']
        if packages:
            return pacman.install_packages(packages)
        return False

    def setup_suricata(self, network_interface=None, stdout=False):
        if not network_interface:
            network_interface = utilities.get_network_interface_names()[0]
        if network_interface not in utilities.get_network_interface_names():
            sys.stderr.write(
                '[-] The network interface that your defined: \'{}\' is invalid. Valid network interfaces: {}\n'.format(
                    network_interface, utilities.get_network_interface_names()))
            return False
        if stdout:
            sys.stdout.write('[+] Creating suricata install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        pf_ring_install = pf_ring.PFRingInstaller()
        if not pf_ring.PFRingProfiler().is_installed:
            if stdout:
                sys.stdout.write('[+] Installing PF_RING kernel modules and dependencies.\n')
                sys.stdout.flush()
                time.sleep(1)
            pf_ring_install.download_pf_ring(stdout=True)
            pf_ring_install.extract_pf_ring(stdout=True)
            pf_ring_install.setup_pf_ring(stdout=True)
        try:
            os.symlink(os.path.join(pf_ring_install.install_directory, 'lib', 'libpcap.so.1'), '/lib/libpcap.so.1')
        except Exception as e:
            sys.stderr.write('[-] Failed to re-link libpcap.so.1 -> /lib/libpcap.so.1: {}\n'.format(e))
        try:
            os.symlink(os.path.join(pf_ring_install.install_directory, 'lib', 'libpfring.so'), '/lib/libpfring.so.1')
        except Exception as e:
            sys.stderr.write('[-] Failed to re-link libpfring.so -> /lib/libpfring.so.1: {}\n'.format(e))
        if stdout:
            sys.stdout.write('\n\n[+] Compiling Suricata from source. This can take up to 5 minutes.\n\n')
            sys.stdout.flush()
            time.sleep(5)
        subprocess.call('./configure --prefix={} --sysconfdir={} --localstatedir=/var/dynamite/suricata '
                        '--enable-pfring --with-libpfring-includes={} -with-libpfring-libraries={}'.format(
            self.install_directory, '/'.join(self.configuration_directory.split('/')[:-1]),
            os.path.join(pf_ring_install.install_directory, 'include'),
            os.path.join(pf_ring_install.install_directory, 'lib')
        ), shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME))

        subprocess.call('make; make install; make install-conf', shell=True, cwd=os.path.join(
            const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME)
        )

        os.mkdir(os.path.join(self.configuration_directory, 'rules'))
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'suricata', 'suricata.yaml'),
                    os.path.join(self.configuration_directory, 'suricata.yaml'))
        utilities.copytree(os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME, 'rules'),
                           self.configuration_directory)
        oink_installer = oinkmaster.OinkmasterInstaller(
            install_directory=os.path.join(self.install_directory, 'oinkmaster'))
        oink_installer.download_oinkmaster(stdout=stdout)
        oink_installer.extract_oinkmaster(stdout=stdout)
        oink_installer.setup_oinkmaster(stdout=stdout)
        oinkmaster.update_suricata_rules(self.configuration_directory,
                                         os.path.join(self.install_directory, 'oinkmaster'))



install_test = SuricataInstaller()
install_test.download_suricata(stdout=True)
install_test.extract_suricata(stdout=True)
install_test.install_dependencies()
install_test.setup_suricata('ens33', stdout=True)


