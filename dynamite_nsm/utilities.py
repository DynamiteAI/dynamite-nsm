# -*- coding: utf-8 -*-

import os
import re
import pwd
import grp
import sys
import crypt
import socket
import shutil
import string
import random
import getpass
import tarfile
import subprocess
import multiprocessing
from contextlib import closing

try:
    from urllib2 import urlopen
    from urllib2 import URLError
    from urllib2 import HTTPError
    from urllib2 import Request
except Exception:
    from urllib.request import urlopen
    from urllib.error import URLError
    from urllib.error import HTTPError
    from urllib.request import Request
    from urllib.parse import urlencode

import progressbar

from dynamite_nsm import const


def copytree(src, dst, symlinks=False, ignore=None):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            try:
                shutil.copytree(s, d, symlinks, ignore)
            except Exception:
                # File exists or handle locked
                pass
        else:
            shutil.copy2(s, d)


def check_pid(pid):
    """
    Check For the existence of a unix pid.

    :return: True, if the process is running
    """
    if pid == -1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def check_socket(host, port):
    """
    Check if a host is listening on a given port

    :param host: The host the service is listening on
    :param port: The port the service is listening on
    :return: True, if a service is listening on a given HOST:PORT
    """
    if isinstance(port, str):
        port = int(port)
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((host, port)) == 0:
            return True
        else:
            return False


def check_user_exists(username):
    """
    :param username: The username of the user to check
    :return: True if the user exists
    """
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def create_dynamite_environment_file():
    env_file = open('/etc/dynamite/environment', 'a')
    env_file.write('')
    env_file.close()
    set_permissions_of_file('/etc/dynamite/environment', 700)


def create_dynamite_root_directory():
    subprocess.call('mkdir -p /opt/dynamite/', shell=True)
    subprocess.call('mkdir -p /etc/dynamite/', shell=True)
    subprocess.call('mkdir -p /tmp/dynamite/install_cache/', shell=True)


def create_dynamite_user(password):
    """
    Create the dynamite user and group

    :param password: The password for the user
    """
    pass_encry = crypt.crypt(password, str(random.randint(10, 99)))
    subprocess.call('useradd -p "{}" -s /bin/bash dynamite'.format(pass_encry), shell=True)


def create_jupyter_user(password):
    """
    Create the jupyter user w/ home

    :param password: The password for the user
    """
    pass_encry = crypt.crypt(password, str(random.randint(10, 99)))
    subprocess.call('useradd -m -p "{}" -s /bin/bash jupyter'.format(pass_encry),
                    shell=True)


def download_file(url, filename, stdout=False):
    """
    Given a URL and destination file name, download the file to local install_cache

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


def download_java(stdout=False):
    for url in open(const.JAVA_MIRRORS, 'r').readlines():
        if download_file(url, const.JAVA_ARCHIVE_NAME, stdout):
            break


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


def extract_java(stdout=False):
    if stdout:
        sys.stdout.write('[+] Extracting: {} \n'.format(const.JAVA_ARCHIVE_NAME))
    try:
        tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.JAVA_ARCHIVE_NAME))
        tf.extractall(path=const.INSTALL_CACHE)
        sys.stdout.write('[+] Complete!\n')
        sys.stdout.flush()
    except IOError as e:
        sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))


def generate_random_password(length=30):
    """
    Generate a random password containing alphanumeric and symbolic characters
    :param length: The length of the password
    :return: The string representation of the password
    """
    tokens = string.ascii_lowercase + string.ascii_uppercase + '0123456789' + '!@#$%^&*()_+'
    return ''.join(random.choice(tokens) for i in range(length))


def get_environment_file_str():
    """
    :return: The contents of the /etc/dynamite/environment file as a giant export string
    """
    export_str = ''
    for line in open('/etc/dynamite/environment').readlines():
        if '=' in line:
            key, value = line.strip().split('=')
            export_str += 'export {}=\'{}\' && '.format(key, value)
    return export_str


def get_environment_file_dict():
    """
    :return: The contents of the /etc/dynamite/environment file as a dictionary
    """
    export_dict = {}
    for line in open('/etc/dynamite/environment').readlines():
        if '=' in line:
            key, value = line.strip().split('=')
            export_dict[key] = value
    return export_dict


def get_memory_available_bytes():
    """
    Get the amount of RAM (in bytes) of the current system

    :return: The number of bytes available in memory
    """
    return os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')


def get_network_interface_names():
    """
    Returns a list of network interfaces available on the system

    :return: A list of network interfaces
    """
    return os.listdir('/sys/class/net')


def get_network_addresses():
    """
    Returns a list of valid IP addresses for the host

    :return: A tuple containing the internal, and external IP address
    """
    valid_addresses = []
    internal_address, external_address = None, None
    try:
        site = str(urlopen("http://checkip.dyndns.org/", timeout=2).read())
        grab = re.findall('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', site)
        external_address = grab[0]
    except (URLError, IndexError, HTTPError):
        pass
    internal_address = socket.gethostbyname(socket.gethostname())
    if internal_address:
        valid_addresses.append(internal_address)
    if external_address:
        valid_addresses.append(external_address)
    return tuple(valid_addresses)


def get_cpu_core_count():
    """
    :return: The count of CPU cores available on the system
    """
    return multiprocessing.cpu_count()


def is_root():
    """
    Determine whether or not the current user is root

    :return: True, if the user is root
    """
    return os.getuid() == 0


def print_dynamite_logo():
    """
    Print the dynamite logo!
    """
    try:
        dynamite_logo =\
            """
            
                  ,,,,,                  ,▄▄▄▄╓
              .▄▓▀▀▀░▀▀▀▓▓╓            ╔▓▓▓▓▓▓▓▀▓
             #∩╓ ▀▓▓▓▓▓▓▓▄▀▓▄         ║▌▓▓▓▓▓▓▓▓╩▓
                ▀▓"▓▓▓▓▓▓▓▓∩▓▄ ,,▄▄▄▓▓▓▌▓▓▓▓▓▓▓▓╦▓
                 ▐▓╙▓▓▓▓▓▓▓▓▐▓▀▀▀^╙└"^^▀▓▀▓▓▓▓▀▒▓`
                 ▐▓]▓▓▓▓▓▓▓▓▐▓           ▀▀▀▀▀▀^
                ▄▓.▓▓▓▓▓▓▓▓Ü▓▀ ╙╙▀█▒▄▄,,
            '#ε╙╙▄▓▓▓▓▓▓▓▀▄▓▌        `╙▀▀▓▓▓▓▄▄╓,        ,,
              "█▓▄▄▓▓▓░▄▓▓▀  ╙╗,            '"▀▀█▓▓▓▓▓▄#╣▓▓▓▓
                 ║▀"▀▀└,       ▀▓▄                 ^▀▀▀▌▓▓▓▓▓╛
                ╔▓      ▓        ▀▓▄,╓╓,                ╙▀▀▀"
               ]▓▌      ╙▌        '▓▓▓▓▓▓⌐
            ╓▄▄▓▓░       ▓▌        ╫▓▓▓▓▓>
         ╓▓▀▓▓▓▓▓▀▓      ╙▓▌        ╙╙▀╙
        ╔▓▒▓▓▓▓▓▓▓░▓      ║▓╕
        ╚▌║▓▓▓▓▓▓▓╩▓       ▓▓
         ▀▓▀▓▓▓▓▀╠▓┘       ╚▓▓
           ▀▀██▀▀╙          ▓▓▓╓
                           ╫▓▓▓▓▓ε
    
            http://dynamite.ai
            """
        print(dynamite_logo)
        print('\n')
    except SyntaxError:
        # Your operating system is super lame :(
        pass


def print_coffee_art():
    """
    Print coffee mug art!
    """
    try:
        coffee_icon = \
            """
        ╭╯╭╯╭╯
        █▓▓▓▓▓█═╮
        █▓▓▓▓▓█▏︱
        █▓▓▓▓▓█═╯
        ◥█████◤
            """
        print(coffee_icon)
        print('\n')
    except SyntaxError:
        # Your operating system is super lame :(
        pass


def prompt_input(message):
    """
    Compatibility function for Python2/3 for taking in input

    :param message: The message appearing next to the input prompt.
    return: The inputted text
    """
    try:
        res = raw_input(message)
    except NameError:
        res =input(message)
    return res


def prompt_password(prompt='Enter a secure password: ', confirm_prompt='Confirm Password: '):
    """
    Prompt user for password, and confirm

    :param prompt: The first password prompt
    :param confirm_prompt: The confirmation prompt
    :return: The password entered
    """
    password = '0'
    confirm_password = '1'
    first_attempt = True
    valid = False
    while password != confirm_password or len(password) < 6 or not valid:
        if not first_attempt:
            sys.stderr.write('[-] Passwords either did not match or were less than 6 characters. Please try again.\n\n')
            sys.stderr.flush()
        elif '"' in password or "'" in password:
            sys.stderr.write('[-] Passwords cannot contain quote characters. Please try again.\n\n')
            sys.stderr.flush()
        else:
            valid = True
        password = getpass.getpass(prompt)
        confirm_password = getpass.getpass(confirm_prompt)
        first_attempt = False
    return password


def run_subprocess_with_status(process, expected_lines=None):
    """
    Run a subprocess inside a wrapper, that hides the output, and replaces with a progressbar

    :param process: The subprocess.Popen instance
    :param expected_lines: The number of stdout lines to expect
    :return: True, if exited with POSIX 0
    """

    i = 0
    widgets = [
        '[+] ', progressbar.Percentage(),
        ' ', progressbar.Bar(),
        ' ', progressbar.ETA()
    ]
    over_max_value = False
    try:
        pb = progressbar.ProgressBar(widgets=widgets, max_value=expected_lines)
    except TypeError:
        pb = progressbar.ProgressBar(widgets=widgets, maxval=expected_lines)
    pb.start()
    while True:
        output = process.stdout.readline().decode()
        if output == '' and process.poll() is not None:
            break
        if output:
            i += 1
            try:
                if not over_max_value:
                    pb.update(i)
            except ValueError:
                if not over_max_value:
                    pb.finish()
                    sys.stdout.write('[+] This process is taking a bit longer than normal, '
                                     'this can occur if resources are currently tapped.\n')
                    sys.stdout.flush()
                    over_max_value = True
        # print(i, process.poll(), output)
    if not over_max_value:
        pb.finish()
    return process.poll()


def setup_java():
    """
    Installs the latest version of OpenJDK
    """
    subprocess.call('mkdir -p /usr/lib/jvm', shell=True)
    try:
        shutil.move(os.path.join(const.INSTALL_CACHE, 'jdk-11.0.2'), '/usr/lib/jvm/')
    except shutil.Error as e:
        sys.stderr.write('[-] JVM already exists at path specified. [{}]\n'.format(e))
        sys.stderr.flush()
    if 'JAVA_HOME' not in open('/etc/dynamite/environment').read():
        subprocess.call('echo JAVA_HOME="/usr/lib/jvm/jdk-11.0.2/" >> /etc/dynamite/environment', shell=True)


def set_ownership_of_file(path, user='dynamite', group='dynamite'):
    """
    Set the ownership of a file given a user/group and a path

    :param path: The path to the file
    :param user: The name of the user
    :param group: The group of the user
    """
    uid = pwd.getpwnam(user).pw_uid
    group = grp.getgrnam(group).gr_gid
    for root, dirs, files in os.walk(path):
        for momo in dirs:
            os.chown(os.path.join(root, momo), uid, group)
        for momo in files:
            if momo == 'environment':
                continue
            os.chown(os.path.join(root, momo), uid, group)


def set_permissions_of_file(file_path, unix_permissions_integer):
    """
    Set the permissions of a file to unix_permissions_integer

    :param file_path: The path to the file
    :param unix_permissions_integer: The numeric representation of user/group/everyone permissions on a file
    """
    subprocess.call('chmod {} {}'.format(unix_permissions_integer, file_path), shell=True)


def update_sysctl(verbose=False):
    """
    Updates the vm.max_map_count and fs.file-max count

    :param verbose: Include output from system utilities
    """
    new_output = ''
    vm_found = False
    fs_found = False
    for line in open('/etc/sysctl.conf').readlines():
        if not line.startswith('#') and 'vm.max_map_count' in line:
            new_output += 'vm.max_map_count=262144\n'
            vm_found = True
        elif not line.startswith('#') and 'fs.file-max' in line:
            new_output += 'fs.file-max=65535\n'
            fs_found = True
        else:
            new_output += line.strip() + '\n'
    if not vm_found:
        new_output += 'vm.max_map_count=262144\n'
    if not fs_found:
        new_output += 'fs.file-max=65535\n'
    with open('/etc/sysctl.conf', 'w') as f:
        f.write(new_output)
    if verbose:
        subprocess.call('sysctl -w vm.max_map_count=262144', shell=True)
        subprocess.call('sysctl -w fs.file-max=65535', shell=True)
        subprocess.call('sysctl -p', shell=True)
    else:
        subprocess.call('sysctl -w vm.max_map_count=262144', shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        subprocess.call('sysctl -w fs.file-max=65535', shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        subprocess.call('sysctl -p', shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)


def update_user_file_handle_limits():
    """
    Updates the max number of file handles the dynamite user can have open
    """
    new_output = ''
    limit_found = False
    for line in open('/etc/security/limits.conf').readlines():
        if line.startswith('dynamite'):
            new_output += 'dynamite    -   nofile   65535'
            limit_found = True
        else:
            new_output += line.strip()
        new_output += '\n'
    if not limit_found:
        new_output += '\ndynamite    -   nofile   65535\n'
    with open('/etc/security/limits.conf', 'w') as f:
        f.write(new_output)


def tail_file(path, n=1, bs=1024):
    """
    Tail the last n lines of a file at a given path

    :param path: The path to the file
    :param n: The last n number of lines
    :param bs: The block-size in bytes
    :return: A list of lines
    """
    f = open(path)
    f.seek(0, 2)
    l = 1-f.read(1).count('\n')
    B = f.tell()
    while n >= l and B > 0:
            block = min(bs, B)
            B -= block
            f.seek(B, 0)
            l += f.read(block).count('\n')
    f.seek(B, 0)
    l = min(l, n)
    lines = f.readlines()[-l:]
    f.close()
    return lines
