import os
import sys
import tarfile
from installer import const
from installer import utilities

CONFIGURATION_DIRECTORY = '/etc/dynamite/logstash/'
INSTALL_DIRECTORY = '/opt/dynamite/logstash/'
LOG_DIRECTORY = '/var/log/dynamite/logstash/'


class LogstashInstaller:

    def __init__(self):
        pass

    @staticmethod
    def download_logstash(stdout=False):
        """
        Download Logstash archive

        :param stdout: Print output to console
        """
        for url in open(const.LOGSTASH_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.LOGSTASH_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_logstash(stdout=False):
        """
        Extract Logstash to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.LOGSTASH_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.LOGSTASH_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

LogstashInstaller().download_logstash(stdout=True)
LogstashInstaller().extract_logstash(stdout=True)