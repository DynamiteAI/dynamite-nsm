import os
import sys
import time
import tarfile
import subprocess

from installer import const
from installer import utilities
from installer import package_manager

INSTALL_DIRECTORY = '/opt/dynamite/pf_ring/'


class PFRingInstaller:

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/pf_ring/)
        """
        self.install_directory = install_directory


    @staticmethod
    def download_pf_ring(stdout=False):
        """
        Download PF_RING archive

        :param stdout: Print output to console
        """
        for url in open(const.PF_RING_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.PF_RING_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_pf_ring(stdout=False):
        """
        Extract PF_RING to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.PF_RING_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.PF_RING_ARCHIVE_NAME))
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
            packages = ['make', 'gcc', 'linux-headers-generic']
        elif pkt_mng.package_manager == 'yum':
            packages = ['make', 'gcc', '"kernel-devel-uname-r == $(uname -r)"']
        if packages:
            return pkt_mng.install_packages(packages)
        return False

    def setup_pf_ring(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [USERLAND].\n\n')
            sys.stdout.flush()
            time.sleep(2)
        subprocess.call('./configure --prefix={} && make install'.format(self.install_directory),
                        cwd=os.path.join(const.INSTALL_CACHE, 'PF_RING-7.4.0', 'userland', 'lib'), shell=True)
        if stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [libpcap].\n\n')
            sys.stdout.flush()
            time.sleep(2)
        subprocess.call('./configure --prefix={} && make install'.format(self.install_directory),
                        cwd=os.path.join(const.INSTALL_CACHE, 'PF_RING-7.4.0', 'userland', 'libpcap'), shell=True)
        if stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [tcpdump].\n\n')
            sys.stdout.flush()
            time.sleep(2)
        subprocess.call('./configure --prefix={} && make install'.format(self.install_directory),
                        cwd=os.path.join(const.INSTALL_CACHE, 'PF_RING-7.4.0', 'userland', 'tcpdump'), shell=True)
        if stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [KERNEL].\n\n')
            sys.stdout.flush()
            time.sleep(2)
        subprocess.call('make && make install', shell=True, cwd=os.path.join(const.INSTALL_CACHE,
                                                                             'PF_RING-7.4.0', 'kernel'))
        subprocess.call('modprobe pf_ring min_num_slots=32768', shell=True, cwd=os.path.join(const.INSTALL_CACHE,
                                                                             'PF_RING-7.4.0', 'kernel'))
        try:
            if 'pf_ring' not in open('/etc/modules').read():
                if stdout:
                    sys.stdout.write('[+] Setting PF_RING kernel module to load at boot.\n')
                subprocess.call('echo pf_ring min_num_slots=32768 >> /etc/modules', shell=True)
        except IOError:
            if os.path.exists('/etc/modules-load.d'):
                pf_ring_module_found = False
                for mod_conf in os.listdir('/etc/modules-load.d/'):
                    mod_conf_path = os.path.join('/etc/modules-load.d', mod_conf)
                    if 'pf_ring' in open(mod_conf_path).read():
                        pf_ring_module_found = True
                        break
                if not pf_ring_module_found:
                    subprocess.call('echo pf_ring min_num_slots=32768 >> /etc/modules-load.d/pf_ring.conf', shell=True)
            else:
                sys.stderr.write('[-] Could not determine a method to enable pf_ring kernel module. '
                                 'You must enable manually.\n')


