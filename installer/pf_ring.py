import os
import sys
import time
import tarfile
import subprocess

from installer import const
from installer import utilities
from installer import package_manager


class PFRingInstaller:

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
        packages = None
        if pkt_mng.package_manager == 'apt-get':
            packages = ['make', 'gcc', 'linux-headers-generic']
        elif pkt_mng.package_manager == 'yum':
            packages = ['make', 'gcc', 'kernel-devel']
        if packages:
            pkt_mng.install_packages(packages)
            return True
        return False

    def setup_pf_ring(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [KERNEL].')
            sys.stdout.flush()
            time.sleep(2)
        subprocess.call('make && make install', shell=True, cwd=os.path.join(const.INSTALL_CACHE, 'PF_RING-7.4.0', 'kernel'))

