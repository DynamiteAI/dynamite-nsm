import os
import sys
import shutil
import getpass
import tarfile
import subprocess
try:
    from urllib2 import urlopen
    from urllib2 import URLError
except Exception:
    from urllib.request import urlopen
    from urllib.error import URLError

ELASTICSEARCH_ARCHIVE_NAME = 'elasticsearch-7.1.1.tar.gz'
JAVA_ARCHIVE_NAME = 'java-11.0.2.tar.gz'
INSTALL_CACHE = os.environ['DYNAMITE_INSTALL_CACHE']
ELASTICSEARCH_MIRRORS = os.environ['ELASTICSEARCH_LINUX_MIRRORS']
JAVA_MIRRORS = os.environ['JAVA_LINUX_MIRRORS']


def is_root():
    return getpass.getuser() == 'root'


def download_file(url, filename, stdout=False):
    """
    :param url: The url to the file to download
    :param filename: The name of the file to store
    :return: None
    """
    response = urlopen(url)
    CHUNK = 16 * 1024
    if stdout:
        sys.stdout.write('Downloading: {} \t|\t Filename: {}\n'.format(url, filename))
        sys.stdout.write('Progress: ')
        sys.stdout.flush()
    try:
        with open(os.path.join(INSTALL_CACHE, filename), 'wb') as f:
            chunk_num = 0
            while True:
                chunk = response.read(CHUNK)
                if stdout:
                    if chunk_num % 100 == 0:
                        sys.stdout.write('+')
                        sys.stdout.flush()
                if not chunk:
                    break
                chunk_num += 1
                f.write(chunk)
            if stdout:
                sys.stdout.write('\nComplete! [{} bytes written]\n'.format((chunk_num + 1) * CHUNK))
                sys.stdout.flush()
    except URLError as e:
        sys.stderr.write('An error occurred while attempting to download file. [{}]'.format(e))
        return False
    return True


class ElasticInstaller:

    INSTALL_DIRECTORY = '/opt/dynamite/elasticsearch/'
    CONFIGURATION_DIRECTORY = '/etc/dynamite/elasticsearch/'

    def __init__(self):
        self.elasticsearch_downloaded = False
        self.elasticsearch_extracted = False
        self.java_downloaded = False
        self.java_extracted = False

    def download_elasticsearch(self, stdout=False):
        for url in open(ELASTICSEARCH_MIRRORS, 'r').readlines():
            if download_file(url, ELASTICSEARCH_ARCHIVE_NAME, stdout):
                self.elasticsearch_downloaded = True
                break

    def download_java(self, stdout=False):
        for url in open(JAVA_MIRRORS, 'r').readlines():
            if download_file(url, JAVA_ARCHIVE_NAME, stdout):
                self.java_downloaded = True
                break

    def extract_elasticsearch(self, stdout=False):
        if stdout:
            sys.stdout.write('Extracting: {} \n'.format(ELASTICSEARCH_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(INSTALL_CACHE, ELASTICSEARCH_ARCHIVE_NAME))
            tf.extractall(path=INSTALL_CACHE)
            sys.stdout.write('Complete!')
            sys.stdout.flush()
            self.elasticsearch_extracted = True
        except IOError as e:
            sys.stderr.write('An error occurred while attempting to extract file. [{}]\n'.format(e))

    def extract_java(self, stdout=False):
        if stdout:
            sys.stdout.write('Extracting: {} \n'.format(JAVA_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(INSTALL_CACHE, JAVA_ARCHIVE_NAME))
            tf.extractall(path=INSTALL_CACHE)
            sys.stdout.write('Complete!')
            sys.stdout.flush()
            self.java_extracted = True
        except IOError as e:
            sys.stderr.write('An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_elasticsearch(self):
        subprocess.call('mkdir -p {}'.format(self.INSTALL_DIRECTORY), shell=True)
        subprocess.call('mkdir -p {}'.format(self.CONFIGURATION_DIRECTORY), shell=True)
        config_paths = [
            'config/elasticsearch.yml',
            'config/jvm.options',
            'config/log4j2.properties'
        ]
        install_paths = [
            'bin/',
            'lib/',
            'logs/',
            'modules/',
            'plugins/'
        ]
        for path in config_paths:
            try:
                shutil.move(os.path.join(INSTALL_CACHE, 'elasticsearch-7.1.1/{}'.format(path)),
                            self.CONFIGURATION_DIRECTORY)
            except shutil.Error as e:
                sys.stderr.write('{} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            try:
                shutil.move(os.path.join(INSTALL_CACHE, 'elasticsearch-7.1.1/{}'.format(path)),
                            self.INSTALL_DIRECTORY)
            except shutil.Error as e:
                sys.stderr.write('{} already exists at this path. [{}]\n'.format(path, e))
        if 'ES_PATH_CONF' not in open('/etc/environment').read():
            subprocess.call('echo ES_PATH_CONF="{}" >> /etc/environment'.format(self.CONFIGURATION_DIRECTORY),
                            shell=True)
        subprocess.call('source /etc/environment', shell=True)

    def setup_java(self):
        subprocess.call('mkdir -p /usr/lib/jvm', shell=True)
        try:
            shutil.move(os.path.join(INSTALL_CACHE, 'jdk-11.0.2'), '/usr/lib/jvm/')
        except shutil.Error as e:
            sys.stderr.write('JVM already exists at path specified. [{}]\n'.format(e))
        try:
            os.symlink('/usr/lib/jvm/jdk-11.0.2/bin/java', '/usr/bin/java')
        except Exception as e:
            sys.stderr.write('Java Sym-link already exists at path specified. [{}]\n'.format(e))
        if 'JAVA_HOME' not in open('/etc/environment').read():
            subprocess.call('echo JAVA_HOME="/usr/lib/jvm/jdk-11.0.2/" >> /etc/environment', shell=True)
        subprocess.call('source /etc/environment', shell=True)

ElasticInstaller().extract_elasticsearch()
ElasticInstaller().setup_elasticsearch()
