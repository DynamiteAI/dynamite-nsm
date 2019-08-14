import os
import sys
import time
import shutil
import tarfile
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop

try:
    from urllib2 import urlopen
    from urllib2 import URLError
except Exception:
    from urllib.request import urlopen
    from urllib.error import URLError


def download_file(url, filename, download_path, stdout=True):
    """
    Given a URL and destination file name, download the file to local install_cache

    :param url: The url to the file to download
    :param filename: The name of the file to store
    :param download_path: destination file path
    :return: None
    """
    response = urlopen(url)
    CHUNK = 16 * 1024
    if stdout:
        sys.stdout.write('[+] Downloading: {} \t|\t Filename: {}\n'.format(url, filename))
        sys.stdout.write('[+] Progress: ')
        sys.stdout.flush()
    try:
        with open(os.path.join(download_path, filename), 'wb') as f:
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
                sys.stdout.write('\n[+] Complete! [{} bytes written]\n'.format((chunk_num + 1) * CHUNK))
                sys.stdout.flush()
    except URLError as e:
        sys.stderr.write('[-] An error occurred while attempting to download file. [{}]\n'.format(e))
        return False
    return True


def extract_archive(archive_path, destination_path, stdout=True):
    if stdout:
        sys.stdout.write('[+] Extracting: {} \n'.format(archive_path))
    try:
        tf = tarfile.open(archive_path)
        tf.extractall(path=destination_path)
        sys.stdout.write('[+] Complete!\n')
        sys.stdout.flush()
    except IOError as e:
        sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))


def post_install_cmds():
    try:
        os.mkdir('/tmp/dynamite')
    except OSError:
        pass
    download_file('https://github.com/vlabsio/dynamite-nsm/raw/master/dist/data/default_configs.tar.gz',
                  'default_configs.tar.gz')
    download_file('https://github.com/vlabsio/dynamite-nsm/raw/master/dist/data/mirrors.tar.gz',
                  'mirrors.tar.gz')
    shutil.rmtree('/tmp/dynamite/', ignore_errors=True)
    shutil.rmtree('/etc/dynamite/mirrors/', ignore_errors=True)
    shutil.rmtree('/etc/dynamite/default_configs/', ignore_errors=True)
    time.sleep(1)
    try:
        print('Copying default_configs -> /etc/dynamite/default_configs')
        extract_archive('default_configs.tar.gz', '/etc/dynamite/default_configs')
        print('Copying mirrors -> /etc/dynamite/mirrors')
        extract_archive('mirrors.tar.gz', '/etc/dynamite/mirrors')
        shutil.copytree('mirrors/', '/etc/dynamite/mirrors')
    except Exception:
        print('[-] config directories already exist')


class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        post_install_cmds()


class PostDevelopCommand(develop):
    def run(self):
        develop.run(self)
        post_install_cmds()

setup(
    name='dynamite-nsm',
    version='0.0.9',
    packages=find_packages(),
    scripts=['scripts/dynamite', 'scripts/dynamite.py'],
    url='http://vlabs.io',
    license='',
    author='Jamin Becker',
    author_email='jamin@vlabs.io',
    description='Dynamite-NSM is an network security monitor with an emphasis on very fast deployment, '
                'minimal configuration, and intuitive management.',
    include_package_data=True,
    cmdclass={
        'install': PostInstallCommand,
        'develop': PostDevelopCommand,
    }
)
