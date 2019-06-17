import os
import sys
from urllib2 import urlopen
from urllib2 import URLError

INSTALL_CACHE = os.environ['DYNAMITE_INSTALL_CACHE']
ELASTICSEARCH_MIRRORS = os.environ['ELASTICSEARCH_LINUX_MIRRORS']
JAVA_MIRRORS = os.environ['JAVA_LINUX_MIRRORS']


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
    except URLError:
        return False
    return True


class ElasticInstaller:

    def __init__(self):
        self.elasticsearch_downloaded = False
        self.java_downloaded = False

    def download_dependencies(self, stdout=False):
        for url in open(JAVA_MIRRORS, 'r').readlines():
            if download_file(url, 'java-11.tar.gz', stdout):
                self.java_downloaded = True
                break

    def download_elasticsearch(self, stdout=False):
        for url in open(ELASTICSEARCH_MIRRORS, 'r').readlines():
            if download_file(url, 'elasticsearch-7.1.1.tar.gz', stdout):
                self.elasticsearch_downloaded = True
                break

