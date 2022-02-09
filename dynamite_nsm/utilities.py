# -*- coding: utf-8 -*-
import math
import crypt
import fcntl
import getpass
import grp
import json
import multiprocessing
import os
import pwd
import pkg_resources
import random
import re
import shutil
import socket
import string
import struct
import subprocess
import sys
import tarfile
import termios
import textwrap
import time
from itertools import zip_longest
from contextlib import closing
from datetime import datetime
from hashlib import md5
from typing import BinaryIO, TextIO, Dict, List, Optional, Tuple, Union
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.request import urlopen

import progressbar
import psutil

from dynamite_nsm import const
from dynamite_nsm import exceptions


class PrintDecorations:

    @staticmethod
    def _get_colormap():
        pddict = PrintDecorations.__dict__
        colormap = {}
        for key, val in pddict.items():
            if not key.startswith("_COLOR"):
                continue
            colormap[key] = val
        return colormap

    @staticmethod
    def colorize(strinput, _color):
        colormap = PrintDecorations._get_colormap()
        avail_colors = [c.replace("_COLOR_", "").lower() for c in colormap.keys()]
        if _color not in avail_colors:
            raise ValueError(f"Not a valid color, must be one of: {avail_colors}")
        color = colormap[f"_COLOR_{_color.upper()}"]
        return f"{color}{strinput}{PrintDecorations._COLOR_END}"

    _COLOR_CYAN = '\033[96m'
    _COLOR_DARKCYAN = '\033[36m'
    _COLOR_BLUE = '\033[94m'
    _COLOR_GREEN = '\033[92m'
    _COLOR_YELLOW = '\033[93m'
    _COLOR_RED = '\033[91m'
    _COLOR_BOLD = '\033[1m'
    _COLOR_UNDERLINE = '\033[4m'
    _COLOR_END = '\033[0m'
    # convenience/code legibility:
    _COLOR_RESET = _COLOR_END


def backup_configuration_file(source_file: str, configuration_backup_directory: str,
                              destination_file_prefix: str) -> None:
    """Backup a configuration file
    Args:
        source_file: The configuration file you wish to backup
        configuration_backup_directory: The destination configuration directory
        destination_file_prefix: The prefix of the file; timestamp is automatically appended in filename
    Returns:
        None
    """

    timestamp = int(time.time())
    destination_backup_config_file = os.path.join(configuration_backup_directory,
                                                  '{}.{}'.format(destination_file_prefix,
                                                                 timestamp))
    try:
        makedirs(configuration_backup_directory, exist_ok=True)
        set_ownership_of_file(configuration_backup_directory)
    except Exception as e:
        raise exceptions.WriteConfigError(
            "General error while attempting to create backup directory at {}; {}".format(configuration_backup_directory,
                                                                                         e))
    try:
        shutil.copy(source_file, destination_backup_config_file)
    except Exception as e:
        raise exceptions.WriteConfigError(
            "General error while attempting to copy {} to {}".format(
                source_file, destination_backup_config_file, e))


def list_backup_configurations(configuration_backup_directory: str) -> List[Dict]:
    """List available backup files in the configuration_backup_directory
    Args:
        configuration_backup_directory: The destination configuration directory backup directory
    Returns:
        A list of dictionaries, where each dictionary contains a filename representing the name of the backup and a UNIX timestamp.
    """

    backups = []
    digits_only_re = re.compile("^([\s\d]+)$")
    try:
        for conf in os.listdir(configuration_backup_directory):
            timestampstr = conf.split('.')[-1]
            if not digits_only_re.match(timestampstr):
                confpath = os.path.join(configuration_backup_directory, conf)
                if os.path.isdir(confpath):
                    for subconf in os.listdir(confpath):
                        timestampstr = subconf.split('.')[-1]
                        if digits_only_re.match(timestampstr):
                            backups.append(
                                {
                                    'filename': subconf,
                                    'filepath': os.path.join(confpath, subconf),
                                    'time': float(timestampstr)
                                }
                            )
                else:
                    # file is not a dir, and does not match expected format with timestamp. skip it.
                    continue
            else:
                backups.append(
                    {
                        'filename': conf,
                        'filepath': os.path.join(configuration_backup_directory, conf),
                        'time': float(timestampstr)
                    }
                )
    except FileNotFoundError:
        return backups
    backups.sort(key=lambda item: item['time'], reverse=True)
    return backups


def restore_backup_configuration(configuration_backup_filepath: str, config_filepath: str) -> bool:
    """Restore a backup file to a configuration folder of choice
    Args:
        configuration_backup_filepath: The full path to the backup file
        config_filepath: The full path to the to-be-restored configuration file
    Returns:
        True, if successful
    """
    try:
        shutil.move(configuration_backup_filepath, config_filepath)
        return True
    except shutil.Error:
        return False
    except FileNotFoundError:
        return False


def check_pid(pid: int) -> bool:
    """:return: True, if the process is running
    Args:
        The process id
    Returns:
        None
    """
    if not pid:
        return False
    if pid == -1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def check_socket(host: str, port: int) -> bool:
    """Check if a host is listening on a given port
    Args:
        host: The host the service is listening on
        port: The port the service is listening on
    Returns:
         True, if a service is listening on a given HOST:PORT
    """
    if isinstance(port, str):
        port = int(port)
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((host, port)) == 0:
            return True
        else:
            return False


def check_user_exists(username: str) -> bool:
    """Check of a UNIX user exists
    Args:
        username: The username of the user to check
    Returns:
        : True if the user exists
    """
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def copytree(src: str, dst: str, symlinks: Optional[bool] = False, ignore: Optional[bool] = None) -> None:
    """Copy a src file or directory to a destination file or directory
    Args:
        src: The source directory
        dst: The destination directory
        symlinks: If True, symlinks will be followed (Default value = False)
        ignore: If True, errors will be ignored
    Returns:
        None
    """
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


def create_dynamite_environment_file() -> None:
    """Creates the dynamite environment file accessible only to the root user.
    Args:

    Returns:
        None
    """
    makedirs(const.CONFIG_PATH, exist_ok=True)
    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    env_file_f = open(env_file, 'a')
    env_file_f.write('')
    env_file_f.close()
    set_ownership_of_file(env_file, user='dynamite', group='dynamite')
    set_permissions_of_file(env_file, 770)


def create_dynamite_user() -> None:
    """Create the dynamite user and group
    Returns:
        None
    """
    password = salt = str(random.randint(10, 99))
    pass_encry = crypt.crypt(password, salt)
    subprocess.call('useradd -r -p "{}" -s /bin/bash dynamite'.format(pass_encry), shell=True)


def create_dynamite_remote_user() -> None:
    """Create the dynamite-remote user and group
    Returns:
        None
    """
    password = salt = str(random.randint(10, 99))
    pass_encry = crypt.crypt(password, salt)
    subprocess.call('useradd -r -p "{}" -s /bin/bash dynamite-remote'.format(pass_encry), shell=True)


def create_jupyter_user(password: str) -> None:
    """Create the jupyter user w/ home
    Args:
        password: The password for the user
    Returns:
        None
    """
    pass_encry = crypt.crypt(password, str(random.randint(10, 99)))
    subprocess.call('useradd -r -m -p "{}" -s /bin/bash jupyter'.format(pass_encry),
                    shell=True)


def delete_dynamite_remote_user() -> None:
    """ Remove the dynamite-remote user
    Returns:
        None
    """
    subprocess.run(['userdel', 'dynamite-remote'])


def download_file(url: str, filename: str, stdout: Optional[bool] = False) -> bool:
    """
    Given a URL and destination file name, download the file to local install_cache

    Args:
        url: The url to the file to download
        filename: The name of the file to write to disk
        stdout: Print the output to the console

    Returns: True, if successfully downloaded.

    """
    CHUNK = 16 * 1024

    makedirs(const.INSTALL_CACHE, exist_ok=True)
    response = urlopen(url)
    try:
        response_size_bytes = int(response.headers['Content-Length'])
    except (KeyError, TypeError, ValueError):
        response_size_bytes = None
    widgets = [
        '\033[92m',
        '{} '.format(datetime.strftime(datetime.utcnow(), '%Y-%m-%d %H:%M:%S')),
        '\033[0m',
        '\033[0;36m'
        'DOWNLOAD_MANAGER ',
        '\033[0m',
        '                    | ',
        progressbar.FileTransferSpeed(),
        ' ', progressbar.Bar(),
        ' ', '({})'.format(filename),
        ' ', progressbar.ETA(),

    ]
    pb = progressbar.ProgressBar(widgets=widgets, maxval=int(response_size_bytes))
    if stdout:
        try:
            pb.start()
        except Exception:
            # Something broke, disable stdout going forward
            stdout = False
    try:
        with open(os.path.join(const.INSTALL_CACHE, filename), 'wb') as f:
            chunk_num = 0
            while True:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                f.write(chunk)
                if stdout:
                    try:
                        pb.update(CHUNK * chunk_num)
                    except ValueError:
                        pass
                chunk_num += 1
            if stdout:
                pb.finish()
    except URLError:
        return False
    return True


def extract_archive(archive_path: str, destination_path: str) -> None:
    """Extract a tar.gz archive to a given destination path.
    Args:
        archive_path: The full path to the tar.gz archive file
        destination_path: The path where the archive will be extracted
    Returns:
        None
    """

    try:
        tf = tarfile.open(archive_path)
        tf.extractall(path=destination_path)
    except IOError:
        pass


def get_optimal_cpu_interface_config(interface_names: List[str], available_cpus: Union[Tuple, List[Tuple]],
                                     custom_ratio: Optional[int] = None):
    def grouper(n, iterable):
        args = [iter(iterable)] * n
        return zip_longest(*args)

    def create_thread_groups(iface_names: List[str], avail_cpus: Tuple):
        idx = 0
        avail_cpus = list(avail_cpus)
        thread_worker_configs = []
        if not avail_cpus:
            return thread_worker_configs
        for iface_name in iface_names:
            if idx >= len(avail_cpus):
                idx = 0
            if isinstance(avail_cpus[idx], int):
                avail_cpus[idx] = [avail_cpus[idx]]

            thread_worker_configs.append(
                dict(
                    interface_name=iface_name,
                    pin_cpus=avail_cpus[idx],
                    thread_count=len(avail_cpus[idx])
                )
            )
            idx += 1
        return thread_worker_configs

    if len(available_cpus) <= len(interface_names):
        cpu_network_interface_config = create_thread_groups(interface_names, available_cpus)
    else:
        ratio = custom_ratio
        if not custom_ratio:
            ratio = int(math.ceil(len(available_cpus) / float(len(interface_names))))
        cpu_groups = grouper(ratio, available_cpus)
        temp_cpu_groups = []
        for cpu_group in cpu_groups:
            cpu_group = [c for c in cpu_group if c]
            temp_cpu_groups.append(tuple(cpu_group))
        cpu_groups = temp_cpu_groups
        cpu_network_interface_config = create_thread_groups(interface_names, tuple(cpu_groups))
    return cpu_network_interface_config


def get_default_agent_tag() -> str:
    """Get the agent tag
    Args:

    Returns:
        The agent tag
    """

    return ''.join([c.lower() for c in str(socket.gethostname()) if c.isalnum()][0:25]) + '_agt'


def get_default_es_node_name() -> str:
    """:return: The node name
    Args:

    Returns:
        The node name.
    """
    return ''.join([c.lower() for c in str(socket.gethostname()) if c.isalnum()][0:25]) + '_es_node'


def get_file_md5_hash(fh: Union[BinaryIO, TextIO]) -> str:
    """Given a file-like object return the md5 hash of that object
    Args:
        fh: file handle (file like object)
    Returns:
         the md5 hash of the file
    """

    block_size = 65536
    md5_hasher = md5()
    buf = fh.read(block_size)
    while len(buf) > 0:
        md5_hasher.update(buf)
        buf = fh.read(block_size)
    return md5_hasher.hexdigest()


def get_filepath_md5_hash(file_path: str) -> str:
    """Given a file-path to return the md5 hash of that file
    Args:
        file_path: path to the file being hashed
    Returns:
         the md5 hash of a file
    """
    with open(file_path, 'rb') as afile:
        return get_file_md5_hash(afile)


def get_terminal_size() -> Optional[Tuple[int, int]]:
    """Returns the width and height of the current terminal
    Args:

    Returns:
         (width, height) of the current terminal
    """
    try:
        h, w, hp, wp = struct.unpack('HHHH',
                                     fcntl.ioctl(0, termios.TIOCGWINSZ,
                                                 struct.pack('HHHH', 0, 0, 0, 0)))
    except Exception:
        return None
    return w, h


def get_sshd_directory_path():
    """Gets the path of the Include directory in the sshd_config

    Returns:
        The path to the sshd_config.d/
    """
    include_directory = None
    with open(const.SSH_CONF_FILE, 'r') as sudoers_in:
        for i, line in enumerate(sudoers_in.readlines()):
            line = line.strip()
            if line.startswith('Include'):
                include_directory = ' '.join(line.split(' ')[1:])
                break
    include_directory = include_directory.replace('*.conf', '')

    return include_directory


def get_sudoers_directory_path():
    """Get the path to the #includedir directory
    Returns:
        The path to sudoers.d/
    """
    include_directory = None
    with open(const.SUDOERS_FILE, 'r') as sudoers_in:
        for i, line in enumerate(sudoers_in.readlines()):
            line = line.strip()
            if line.startswith('#includedir') or line.startswith('@includedir'):
                include_directory = ' '.join(line.split(' ')[1:])
                break
    return include_directory


def generate_random_password(length: int = 30) -> str:
    """Generate a random password containing alphanumeric and symbolic characters
    Args:
        length: The length of the password
    Returns:
         The string representation of the password
    """
    tokens = string.ascii_lowercase + string.ascii_uppercase + '0123456789' + '!@#$%^&*()_+'
    return ''.join(random.choice(tokens) for i in range(length))


def get_environment_file_str() -> str:
    """Get the contents of the dynamite environment file as a string.
    Args:

    Returns:
         The contents of the /etc/dynamite/environment file as a giant export string
    """

    export_str = ''
    with open(os.path.join(const.CONFIG_PATH, 'environment')) as env_f:
        for line in env_f.readlines():
            if '=' in line:
                key, value = line.strip().split('=')
                export_str += 'export {}=\'{}\' && '.format(key, value)
    return export_str


def get_environment_file_dict() -> Dict:
    """Get the contents of the dynamite environment file as a dictionary.
    Args:

    Returns:
         The contents of the /etc/dynamite/environment file as a dictionary
    """
    export_dict = {}
    try:
        for line in open(os.path.join(const.CONFIG_PATH, 'environment')).readlines():
            if '=' in line:
                key, value = line.strip().split('=')
                export_dict[key] = value
    except PermissionError:
        return {}
    except FileNotFoundError:
        return {}
    return export_dict


def get_epoch_time_seconds() -> int:
    """Get the number of seconds since 01/01/1970

    Returns: An integer representing the number of seconds between 01/01/1970 and now.
    """
    return int(time.time())


def get_memory_available_bytes() -> int:
    """Get the amount of RAM (in bytes) of the current system
    Args:

    Returns:
         The number of bytes available in memory
    """
    return os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')


def get_network_interface_names() -> List[str]:
    """Returns a list of network interfaces available on the system
    Args:

    Returns:
         A list of network interfaces
    """
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    available_networks = []
    for intface, addr_list in addresses.items():
        if intface.startswith('lo'):
            continue
        elif intface.startswith('docker'):
            continue
        elif intface.startswith('veth'):
            continue
        elif intface.startswith('br-'):
            continue
        elif intface not in stats:
            continue
        available_networks.append(intface)
    return available_networks


def get_network_interface_configurations() -> List[Dict]:
    """Returns a list of network interfaces available on the system
    Args:

    Returns:
         A list of network interfaces
    """

    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    available_networks = []
    for intface, addr_list in addresses.items():
        if intface.startswith('lo'):
            continue
        elif intface.startswith('docker'):
            continue
        elif intface.startswith('veth'):
            continue
        elif intface.startswith('br-'):
            continue
        elif intface not in stats:
            continue
        name = intface
        speed = stats[intface].speed
        duplex = str(stats[intface].duplex)
        mtu = stats[intface].mtu
        available_networks.append({
            'name': name,
            'speed': speed,
            'duplex': duplex,
            'mtu': mtu
        })
    return available_networks


def get_network_addresses() -> Tuple:
    """Returns a list of valid IP addresses for the host
    Args:

    Returns:
         A tuple containing an internal, and external IP address
    """
    valid_addresses = []
    internal_address, external_address = None, None
    try:
        site = str(urlopen("http://checkip.dyndns.org/", timeout=2).read())
        grab = re.findall(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', site)
        external_address = grab[0]
    except (URLError, IndexError, HTTPError):
        pass
    internal_address = socket.gethostbyname(socket.gethostname())
    if internal_address:
        valid_addresses.append(internal_address)
    if external_address:
        valid_addresses.append(external_address)
    return tuple(valid_addresses)


def get_primary_ip_address() -> str:
    """Get the IP address for the default route out.
    Args:

    Returns:
        The IP address of the primary (default route) interface
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def get_cpu_core_count() -> int:
    """Get the number of availble CPU cores
    Args:

    Returns:
         The count of CPU cores available on the system
    """
    return multiprocessing.cpu_count()


def is_root() -> bool:
    """Determine whether or not the current user is root
    Args:

    Returns:
         True, if the user is root
    """
    return os.getuid() == 0


def is_dynamite_member(user: str) -> bool:
    """
    Check if a user is a member of the dynamite group
    Args:
        user: A username

    Returns:
        True, if the user is a member of the dynamite group
    """
    group = grp.getgrnam('dynamite')
    return user in group[3]


def is_setup() -> bool:
    """Check if DynamiteNSM has required directories created.
    Returns:
        True if setup properly
    """
    if not os.path.exists(const.CONFIG_PATH):
        return False
    elif not os.path.exists(const.INSTALL_PATH):
        return False
    elif not os.path.exists(const.LOG_PATH):
        return False
    return True


def makedirs(path: str, exist_ok: Optional[bool] = True) -> None:
    """Create directory(ies) at a given path
    Args:
        path: The path to the directories
        exist_ok: If it exists, create anyway (Default value = True)
    Returns:
        None
    """
    if exist_ok:
        os.makedirs(path, exist_ok=True)
    else:
        os.makedirs(path)


def print_dynamite_lab_art() -> None:
    """Print the dynamite lab ascii art
    Args:

    Returns:
        None
    """

    try:
        lab_art = \
            """
            \033[0;36m
               _
              | | DynamiteLab         |
              / \  is an experimental |
             /   \  feature.          |
            (_____)  Happy Hacking!   |    ~The Dynamite Team~
            \033[0m
            """
        print(lab_art)
    except (SyntaxError, UnicodeEncodeError):
        print()


def print_dynamite_logo(version: str) -> None:
    """Print the dynamite logo!
    Args:

    Returns:
        None
    """
    try:
        dynamite_logo = \
            """
            \033[0;36m
            
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
            \033[0m
            http://dynamite.ai
            
            Version: {}
            
            """.format(version)
        print(dynamite_logo)
        print('\n')
    except (SyntaxError, UnicodeEncodeError):
        print('http://dynamite.ai\n\nVersion: {}\n'.format(version))


def print_coffee_art() -> None:
    """Print the dynamite logo!
    Args:

    Returns:
        None
    """
    try:
        coffee_icon = \
            """
        ╭╯╭╯╭╯
        █▓▓▓▓▓█═╮
        █▓▓▓▓▓█▏︱
        █▓▓▓▓▓█═╯
        ◥█████◤      ~~~ "Have a cup of coffee while you wait." ~~~
            """
        print(coffee_icon)
        print('\n')
    except (SyntaxError, UnicodeEncodeError):
        # Your operating system is super lame :(
        pass


def prompt_input(message: str, valid_responses: Optional[List] = None) -> str:
    """Taking in input
    Args:
        message: The message appearing next to the input prompt.
        valid_responses: A list of expected responses
    Returns:
         The inputted text
    """

    res = input(message)
    if valid_responses:
        while str(res).strip() not in [str(r) for r in valid_responses]:
            print(f'Please enter a valid value: {valid_responses}')
            res = input(message)
    return res


def prompt_password(prompt='[?] Enter a secure password: ', confirm_prompt='[?] Confirm Password: ') -> str:
    """Prompt user for password, and confirm
    Args:
        prompt: The first password prompt
        confirm_prompt: The confirmation prompt
    Returns:
         The password entered
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


def run_subprocess_with_status(process: subprocess.Popen, expected_lines: Optional[int] = None) -> int:
    """Run a subprocess inside a wrapper, that hides the output, and replaces with a progressbar
    Args:
        process: The subprocess.Popen instance
        expected_lines: The number of stdout lines to expect
    Returns:
         The exit code.
    """

    i = 0
    widgets = [
        '\033[92m',
        '{} '.format(datetime.strftime(datetime.utcnow(), '%Y-%m-%d %H:%M:%S')),
        '\033[0m',
        '\033[0;36m',
        'PROCESS_TRACKER ',
        '\033[0m',
        '           | ',
        progressbar.Percentage(),
        ' ', progressbar.Bar(),
        ' ', progressbar.FormatLabel(''),
        ' ', progressbar.ETA()
    ]
    over_max_value = False
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
                    widgets[11] = '<{0}...>'.format(str(output).replace('\n', '').replace('\t', '')[0:40])
                    pb.update(i)
            except ValueError:
                if not over_max_value:
                    pb.finish()
                    over_max_value = True
        # print(i, process.poll(), output)
    if not over_max_value:
        pb.finish()
    return process.poll()


def safely_remove_file(path: str) -> None:
    """Remove a file if it exists at the given path
    Args:
        path: The path of the file to remove
    Returns:
        None
    """
    if os.path.exists(path):
        os.remove(path)


def set_ownership_of_file(path: str, user: Optional[str] = 'dynamite', group: Optional[str] = 'dynamite') -> None:
    """Set the ownership of a file given a user/group and a path
    Args:
        path: The path to the file
        user: The name of the user
        group: The group of the user
    Returns:
        None
    """

    uid = pwd.getpwnam(user).pw_uid
    group = grp.getgrnam(group).gr_gid
    os.chown(path, uid, group)
    for root, dirs, files in os.walk(path):
        for momo in dirs:
            os.chown(os.path.join(root, momo), uid, group)
        for momo in files:
            if momo == 'environment':
                continue
            os.chown(os.path.join(root, momo), uid, group)


def set_permissions_of_file(file_path: str, unix_permissions_integer: Union[str, int]) -> None:
    """Set the permissions of a file to unix_permissions_integer
    Args:
        file_path: The path to the file
        unix_permissions_integer: The numeric representation of user/group/everyone permissions on a file
    Returns:
        None
    """
    subprocess.call('chmod -R {} {}'.format(unix_permissions_integer, file_path), shell=True)


def test_bpf_filter(expr: str, include_message: bool = False) -> Union[bool, Tuple[bool, str]]:
    """Given a BPF expression determine if it is valid, and optionally return a message if not
    Args:
        expr: A valid Berkeley Packet Filter
        include_message: If True, Include an error message if expression is not valid.

    Returns:
        The result and optional result message
    """
    bin_path = pkg_resources.resource_filename('dynamite_nsm', 'bin/bpf_validate')
    set_permissions_of_file(bin_path, '+x')
    p = subprocess.Popen([bin_path] + expr.split(' '), stdout=subprocess.PIPE)
    output, _ = p.communicate()
    serialized_values = json.loads(output)
    if not include_message:
        return serialized_values['success']
    else:
        return serialized_values['success'], serialized_values['msg']


def update_sysctl(verbose: Optional[bool] = False) -> None:
    """Updates the vm.max_map_count and fs.file-max count
    Args:
        verbose: Include output from system utilities
    Returns:
        None
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


def update_user_file_handle_limits() -> None:
    """Updates the max number of file handles the dynamite user can have open
    Args:

    Returns:
        None
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


def wrap_text(s: str) -> str:
    """Given a string adds newlines based on the current size of the terminal window (if one is found)
    Args:
        s: A string
    Returns:
         A new line delaminated string
    """
    if not s:
        return ""
    term_dim = get_terminal_size()
    if not term_dim:
        w, h = 150, 90
    else:
        w, h = term_dim
    wrapped_s = '\n'.join(textwrap.wrap(s, w - 40, fix_sentence_endings=True))
    return wrapped_s
