import os
import sys
import time
import signal
import shutil
import tarfile
import subprocess
from multiprocessing import Process
from lib import const
from lib import utilities

INSTALL_DIRECTORY = '/opt/dynamite/filebeats/'


class FileBeatInstaller:

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        self.install_directory = install_directory

    @staticmethod
    def download_filebeat(stdout=False):
        """
        Download Filebeat archive

        :param stdout: Print output to console
        """
        for url in open(const.FILE_BEAT_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.FILE_BEAT_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_filebeat(stdout=False):
        """
        Extract Filebeat to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.FILE_BEAT_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            if stdout:
                sys.stdout.write('[+] Complete!\n')
                sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_filebeat(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating Filebeat install directory.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        utilities.copytree(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_DIRECTORY_NAME), self.install_directory)