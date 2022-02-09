import os
import tarfile
import subprocess

from typing import Optional, Tuple, Union

USER_HOME = os.environ.get("HOME")
LOCK_PATH = f'{USER_HOME}/.dynamite_remote/locks'
REMOTE_SSH_USER = 'dynamite-remote'


class NodeLocked(Exception):
    """
    Thrown a remote node is already running a command
    """

    def __init__(self, hostname, command):
        msg = f'{hostname.strip()} is already running \'{command.strip()}\''
        super(NodeLocked, self).__init__(msg)


def create_new_remote_keypair(node_name) -> Tuple[int, str, str]:
    temp_key_root = '/tmp/dynamite-remote/keys/'
    makedirs(temp_key_root)
    p = subprocess.Popen(
        f'cat /dev/zero | ssh-keygen -t rsa -b 4096 -f {temp_key_root}/{node_name} -N ""', shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    out, err = p.communicate()
    return p.returncode, out.decode('utf-8'), err.decode('utf-8')


def execute_over_ssh(*args):
    cmd = ['bash', f'{os.environ.get("HOME")}/.dynamite_remote/bin/ssh_wrapper.sh']
    cmd.extend(args)
    ssh_subprocess = subprocess.Popen(cmd)
    ssh_subprocess.communicate()


def execute_dynamite_command_on_remote_host(host_or_ip: str, port: int, private_key_path: str,
                                            *dynamite_arguments):
    makedirs(LOCK_PATH)

    def is_locked():
        return host_or_ip in os.listdir(LOCK_PATH)

    remote_cmd = [f'{REMOTE_SSH_USER}@{host_or_ip}', '-p', str(port), '-t', '-i', private_key_path]
    local_command = ['sudo', '/usr/local/bin/dynamite']
    local_command.extend(dynamite_arguments)
    remote_cmd.extend(local_command)
    if is_locked():
        with open(f'{LOCK_PATH}/{host_or_ip}') as node_lock:
            command = node_lock.read()
            raise NodeLocked(host_or_ip, command)
    execute_over_ssh(*remote_cmd)


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


def safely_remove_file(path: str) -> None:
    """Remove a file if it exists at the given path
    Args:
        path: The path of the file to remove
    Returns:
        None
    """
    if os.path.exists(path):
        os.remove(path)


def set_permissions_of_file(file_path: str, unix_permissions_integer: Union[str, int]) -> None:
    """Set the permissions of a file to unix_permissions_integer
    Args:
        file_path: The path to the file
        unix_permissions_integer: The numeric representation of user/group/everyone permissions on a file
    Returns:
        None
    """
    subprocess.call('chmod -R {} {}'.format(unix_permissions_integer, file_path), shell=True)


def search_for_config():
    locations = [f'{os.environ.get("HOME")}/.dynamite_remote/config.cfg',
                 '/etc/dynamite-remote/config.cfg',
                 '../config.cfg', './config.cfg']
    for fp in locations:
        if os.path.exists(fp):
            return fp
    return None
