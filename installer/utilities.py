import os
import pwd
import grp
import sys
import crypt
import shutil
import getpass
import subprocess

try:
    from urllib2 import urlopen
    from urllib2 import URLError
except Exception:
    from urllib.request import urlopen
    from urllib.error import URLError

from installer import const


def is_root():
    return getpass.getuser() == 'root'


def get_memory_available_bytes():
    return os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')


def create_dynamite_user(password):
    pass_encry = crypt.crypt(password)
    subprocess.call('useradd -p "{}" -s /bin/bash dynamite'.format(pass_encry), shell=True)


def download_file(url, filename, stdout=False):
    """
    :param url: The url to the file to download
    :param filename: The name of the file to store
    :return: None
    """
    response = urlopen(url)
    CHUNK = 16 * 1024
    if stdout:
        sys.stdout.write('[+] Downloading: {} \t|\t Filename: {}\n'.format(url, filename))
        sys.stdout.write('[+] Progress: ')
        sys.stdout.flush()
    try:
        with open(os.path.join(const.INSTALL_CACHE, filename), 'wb') as f:
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


def set_ownership_of_file(path):
    uid = pwd.getpwnam('dynamite')
    group = grp.getgrgid('nogroup')
    for root, dirs, files in os.walk(path):
        for momo in dirs:
            os.chown(os.path.join(root, momo), uid, group)
        for momo in files:
            os.chown(os.path.join(root, momo), uid, group)


def update_vm_max_map_count():
    new_output = ''
    found = False
    for line in open('/etc/sysctl.conf').readlines():
        if not line.startswith('#') and 'vm.max_map_count' in line:
            new_output += 'vm.max_map_count=262144'
            found = True
        else:
            new_output += line
        new_output += '\n'
    if not found:
        new_output += 'vm.max_map_count=262144'
    open('/etc/sysctl.conf', 'w').write(new_output)
    subprocess.call('sysctl -w vm.max_map_count=262144', shell=True)
