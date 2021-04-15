import json
import os
import shutil
import subprocess
import tarfile
from typing import Optional

from dynamite_nsm import utilities, exceptions
from dynamite_nsm.services.base import install


class SSHKeyCreationError(exceptions.InstallError):
    """
    Thrown when ssh-keygen process exits with a non-zero error code
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while creating ssh key for dynamite-remote user: {}".format(message)
        super(SSHKeyCreationError, self).__init__(msg)


class InstallManager(install.BaseInstallManager):

    def __init__(self, node_name: str, stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        """ Install a new
        Args:
            node_name: The name of the node to install
            stdout: Print output to console
            verbose: Include detailed debug messages
        """
        super().__init__('node', verbose, stdout)
        self.node_name = node_name

    @staticmethod
    def patch_sshd_config() -> None:
        """Locate and patch the sshd_config file with logic to allow only pubkey auth for dynamite-remote user.
        Returns:
            None
        """
        sshd_config_location = None
        sshd_config_addition = '''
        
        Match User dynamite-remote
            PasswordAuthentication no
            PubkeyAuthentication yes
        '''

        probable_sshd_locations = ['/etc/ssh/sshd_config']
        for loc in probable_sshd_locations:
            if os.path.exists(loc):
                sshd_config_location = loc
                break
        if sshd_config_location:
            with open(sshd_config_location, 'r') as sshd_config_in:
                if 'Match User dynamite-remote' not in sshd_config_in.read():
                    with open(sshd_config_location, 'a') as sshd_config_out:
                        sshd_config_out.write(sshd_config_addition)

    @staticmethod
    def patch_sudoers_file() -> None:
        """Add logic to allow the dynamite-remote user root access to invoke dynamite commandline utility w/o a password
        Returns:
            None
        """
        sudoers_file_location = None
        sudoers_file_addition = 'dynamite-remote ALL=(ALL) NOPASSWD: /usr/local/bin/dynamite'
        probable_sudoers_locations = ['/etc/sudoers']
        for loc in probable_sudoers_locations:
            if os.path.exists(loc):
                sudoers_file_location = loc
                break
        if sudoers_file_location:
            with open(sudoers_file_location, 'r') as sudoers_file_in:
                if sudoers_file_addition not in sudoers_file_in.read():
                    with open(sudoers_file_location, 'a') as sudoers_file_out:
                        sudoers_file_out.write(sudoers_file_addition)

    def create_dynamite_remote_keypair(self) -> None:
        """Create a public/private RSA key allowing the dynamite-remote user to login via SSH
        Returns:
            None
        """
        temp_key_root = '/tmp/dynamite/keys/'
        ssh_pub_key_root = f'/home/dynamite-remote/.ssh/'
        ssh_pub_key_path = f'{ssh_pub_key_root}{self.node_name}.pub'
        utilities.makedirs(temp_key_root)
        utilities.makedirs(ssh_pub_key_root)
        utilities.safely_remove_file(f'{temp_key_root}/{self.node_name}')
        p = subprocess.Popen(
            f'cat /dev/zero | ssh-keygen -t rsa -b 4096 -f {temp_key_root}/{self.node_name} -N ""', shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = p.communicate()
        if p.returncode == 0:
            # Move the public key to /home/dynamite-remote/.ssh/{node_name}.pub
            shutil.move(f'{temp_key_root}/{self.node_name}.pub', ssh_pub_key_path)
            utilities.set_ownership_of_file(ssh_pub_key_path, user='dynamite-remote', group='dynamite')
            utilities.set_permissions_of_file(ssh_pub_key_path, '644')
        else:
            raise SSHKeyCreationError(message=f'stdout: {out}; stderr: {err}')

    def setup(self, host: str, port: Optional[int] = 22, description: Optional[str] = None) -> None:
        """ Install node to remotely manage this instance of DynamiteNSM
        Args:
            host: A host or IP address that is accessible to the computer you are running dynamite-remote on.
            port: The port SSH is using
            description: A description of this node

        Returns:
            None
        """
        node_name = self.dynamite_environ.get('DYNAMITE_NODE_NAME')
        if node_name:
            self.logger.error('This instance has already been setup for remote management.')
            raise exceptions.InstallError(
                f'{self.node_name} is already installed. Please uninstall it first and re-install to create a new '
                f'authentication package.')
        temp_key_root = '/tmp/dynamite/keys'
        temp_manifests_root = '/tmp/dynamite/auth_manifests'
        auth_manifest_path = f'{temp_manifests_root}/metadata.json'
        auth_priv_key_path = f'{temp_key_root}/{self.node_name}'
        auth_package_name = f'{self.node_name}_auth.tar.gz'

        utilities.create_dynamite_remote_user()
        utilities.makedirs(temp_manifests_root)
        self.create_dynamite_remote_keypair()
        self.patch_sshd_config()
        self.patch_sudoers_file()
        if not description:
            description = f'DynamiteNSM node on {host}:{port} | ' \
                          f'RAM (Bytes): {utilities.get_memory_available_bytes()} | ' \
                          f'CPU Cores: {utilities.get_cpu_core_count()}'
        with open(auth_manifest_path, 'w') as manifest_out:
            manifest_content = json.dumps({
                'name': self.node_name,
                'host': host,
                'port': port,
                'description': description

            })
            manifest_out.write(manifest_content)
            self.logger.debug('Writing: ' + manifest_content)
        with tarfile.open(auth_package_name, 'w:gz') as tar_out:
            tar_out.add(
                auth_priv_key_path, arcname=os.path.split(auth_priv_key_path)[1]
            )
            tar_out.add(
                auth_manifest_path, arcname=os.path.split(auth_manifest_path)[1]
            )
        self.create_update_env_variable('DYNAMITE_NODE_NAME', self.node_name)

        self.logger.info(f'An authentication package has been created and is available here: {auth_package_name}. '
                         f'To use copy this archive over to a computer where dynamite-remote is installed, and run: '
                         f'\'dynamite-remote install {auth_package_name}.\'')


class UninstallManager(install.BaseUninstallManager):

    """
    Uninstall Dynamite Node
    """

    def __init__(self, stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        """
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """
        self.delete_env_variable('DYNAMITE_NODE_NAME')
        super().__init__('node', ['/home/dynamite-remote/.ssh'], stdout=stdout, verbose=verbose)
        utilities.delete_dynamite_remote_user()
