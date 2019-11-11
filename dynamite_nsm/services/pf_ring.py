import os
import sys
import json
import time
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager

INSTALL_DIRECTORY = '/opt/dynamite/pf_ring/'


class PFRingInstaller:
    """
    An interface for installing PF_RING kernel module and UserLand requirements
    """

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/pf_ring/)
        """
        self.install_directory = install_directory

    def _compile_pf_ring_modules(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [USERLAND].\n\n')
            sys.stdout.flush()
            time.sleep(2)
        subprocess.call('./configure --prefix={} && make install'.format(self.install_directory),
                        cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'userland', 'lib'),
                        shell=True)
        if stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [libpcap].\n\n')
            sys.stdout.flush()
            time.sleep(2)
        subprocess.call('./configure --prefix={} && make install'.format(self.install_directory),
                        cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'userland', 'libpcap'),
                        shell=True)
        if stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [tcpdump].\n\n')
            sys.stdout.flush()
            time.sleep(2)
        subprocess.call('./configure --prefix={} && make install'.format(self.install_directory),
                        cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'userland', 'tcpdump'),
                        shell=True)
        if stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [KERNEL].\n\n')
            sys.stdout.flush()
            time.sleep(2)
        subprocess.call('make && make install', shell=True, cwd=os.path.join(const.INSTALL_CACHE,
                                                                             const.PF_RING_DIRECTORY_NAME, 'kernel'))
        subprocess.call('modprobe pf_ring min_num_slots=32768', shell=True, cwd=os.path.join(const.INSTALL_CACHE,
                                                                             const.PF_RING_DIRECTORY_NAME, 'kernel'))

    def _create_pf_ring_environment_variables(self, stdout=False):
        if 'PF_RING_HOME' not in open('/etc/dynamite/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating PF_RING default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo PF_RING_HOME="{}" >> /etc/dynamite/environment'.format(self.install_directory),
                            shell=True)

    @staticmethod
    def _setup_pf_ring_kernel_modules(stdout=False):
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
                                 'You must enable manually using a tool such as \'modprobe\'.\n')

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
        """
        Install required PF_RING dependencies

        :return: True, if packages were successfully installed
        """
        pkt_mng = package_manager.OSPackageManager()
        if not pkt_mng.refresh_package_indexes():
            return False
        packages = None
        if pkt_mng.package_manager == 'apt-get':
            packages = ['make', 'gcc', 'linux-headers-generic']
        elif pkt_mng.package_manager == 'yum':
            packages = ['make', 'gcc', 'kernel-devel-$(uname -r)']
        if packages:
            return pkt_mng.install_packages(packages)
        return False

    def setup_pf_ring(self, stdout=False):
        """
        Compile and setup required binaries and kernel modules

        :param stdout: Print output to console
        """
        self._compile_pf_ring_modules(stdout=stdout)
        self._setup_pf_ring_kernel_modules(stdout=stdout)
        self._create_pf_ring_environment_variables(stdout=stdout)


class PFRingProfiler:
    """
    An Interface for determining whether PF_RING is installed/configured/running properly.
    """
    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_running = self._is_running()

    def __str__(self):
        return json.dumps({
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }, indent=1)

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.PF_RING_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] PF_RING installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        pf_ring_home = env_dict.get('PF_RING_HOME')
        if not pf_ring_home:
            if stderr:
                sys.stderr.write('[-] PF_RING installation directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(pf_ring_home):
            if stderr:
                sys.stderr.write('[-] PF_RING installation directory could not be located on disk at: {}.\n'.format(
                    pf_ring_home))
            return False
        pf_ring_home_files_and_dirs = os.listdir(pf_ring_home)
        if 'bin' not in pf_ring_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate PF_RING {}/bin directory.\n'.format(pf_ring_home))
            return False
        if 'lib' not in pf_ring_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate PF_RING {}/lib directory.\n'.format(pf_ring_home))
            return False
        return True

    @staticmethod
    def _is_running():
        p = subprocess.Popen('lsmod', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, close_fds=True)
        out, err = p.communicate()
        return 'pf_ring' in out.decode('utf-8')

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }



