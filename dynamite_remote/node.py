import io
import os
import time
import json
import shutil
import socket
import tarfile
import logging
import datetime

from typing import Dict, Optional

import daemon
import daemon.pidfile
import tabulate

from sqlalchemy.exc import IntegrityError, NoResultFound

from dynamite_remote.database import db, models
from dynamite_remote import logger, utilities, const

user_home = os.environ.get('HOME')

AUTH_PATH = f'{user_home}/.dynamite_remote/auth'


def print_nodes() -> None:
    """ Print the nodes that are currently installed to the console
    Returns: None
    """
    headers = [
        'Name', 'Host', 'Port', 'Description', 'Commands Invoked', 'Last Invoke Time'
    ]
    rows = []
    for node in db.db_session.query(models.Node).all():
        row = [node.name, node.host, node.port, node.description, node.invoke_count, node.last_invoked_at]
        rows.append(row)
    print(tabulate.tabulate(rows, headers=headers, tablefmt='fancy_grid'))


class Node:

    def __init__(self, name: str, verbose: Optional[bool] = False, stdout: Optional[bool] = False):
        """ Work with an existing node or create a new one
        Args:
            name: The name of the node
            verbose: If True, debug level logs will be printed
            stdout: If True, print logs to console
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = logger.get_logger('dynamite_remote', stdout=stdout, level=log_level)
        self.name = name
        self.key_path = f'{AUTH_PATH}/{self.name}'

    @classmethod
    def create_from_host_str(cls, hoststr: str, verbose: Optional[bool] = False, stdout: Optional[bool] = False):
        """Alternative method for creating a node from a ip:port pairing
        Args:
            hoststr: A host or ip and the port that SSH server is running on.
            verbose: If True, debug level logs will be printed
            stdout: If True, print logs to console

        Returns: A `Node` instance

        """
        if ':' in hoststr:
            host, port = hoststr.split(':')
            port = int(port)
        else:
            host = hoststr
            port = 22
        metadata = db.db_session.query(models.Node). \
            filter(models.Node.host == host and models.Node.port == port). \
            one()
        return cls(metadata.name, verbose, stdout)

    def installed(self) -> bool:
        """Check if this node has been installed
        Returns: True, if the node has been installed
        """
        return bool(self.get_metadata())

    def get_metadata(self) -> Optional[models.Node]:
        """Get the corresponding metadata associated with this node
        Returns: The SQLAlchemy model containing metadata associated with the node.
        """
        try:
            metadata = db.db_session.query(models.Node). \
                filter(models.Node.name == self.name). \
                one()
        except NoResultFound:
            return None
        return metadata

    def remove(self) -> None:
        """ Remove the node metadata and private key from this computer
        Returns: None

        """
        install_priv_key_file_path = f'{AUTH_PATH}/{self.name}'
        db.db_session.query(models.Node).filter_by(name=self.name).delete()
        db.db_session.commit()
        utilities.safely_remove_file(install_priv_key_file_path)
        self.logger.info(f'{self.name} was successfully removed.')

    def install(self, host: str, port: int, description: str, constants: Optional[Dict] = None):
        """Install a new node
        Args:
            host: The host or ip address of the remote node
            port: The port on which SSH runs
            description: A description of the node (E.G windows server sensor)
            constants: A dictionary containing a list of constants associated with this remote node

        Returns: A instance of the node

        """

        def generate_keypair():
            tmp_key_root = '/tmp/dynamite-remote/keys/'
            tmp_priv_key_path = f'{tmp_key_root}/{self.name}'
            install_priv_key_file_path = f'{AUTH_PATH}/{self.name}'
            shutil.rmtree(tmp_key_root, ignore_errors=True)
            ret, stdout, stderr = utilities.create_new_remote_keypair(node_name=self.name)
            if ret != 0:
                self.logger.error(f'An [error {ret}] occurred while attempting to generate keypair via ssh-keygen: '
                                  f'{stdout}; {stderr}')
                exit(1)
            utilities.makedirs(AUTH_PATH)
            utilities.set_permissions_of_file(AUTH_PATH, 700)
            with open(tmp_priv_key_path, 'r') as key_in:
                with open(install_priv_key_file_path, 'w') as key_out:
                    key_out.write(key_in.read())
            utilities.set_permissions_of_file(install_priv_key_file_path, 600)

        def create_auth_package():
            tmp_pub_key_path = f'/tmp/dynamite-remote/keys/{self.name}.pub'
            metadata_info = dict(
                node_name=self.name,
                hostname=socket.gethostname(),
                dynamite_remote_version=const.VERSION
            )
            metadata_f = io.BytesIO()
            data = json.dumps(metadata_info).encode('utf-8')
            metadata_f.write(data)
            metadata_f.seek(0)
            with tarfile.open(self.name + '.tar.gz', 'w:gz') as tar_out:
                tar_out.add(
                    tmp_pub_key_path, arcname='key.pub'
                )
                tarinfo = tarfile.TarInfo('metadata.json')
                tarinfo.size = len(data)
                tar_out.addfile(tarinfo, metadata_f)

        self.logger.info('Initializing Database.')
        db.init_db()
        new_node = models.Node(
            name=self.name,
            host=host,
            port=port,
            description=description
        )
        db.db_session.add(new_node)
        try:
            db.db_session.commit()
        except IntegrityError as e:
            if 'UNIQUE' in str(e):
                self.logger.error('A node with this name or host has already been installed. '
                                  'Please uninstall first then try again.')
                exit(1)
        self.logger.debug(f'Node entry created: {self.name, host, description}')
        generate_keypair()
        self.logger.debug(f'{self.name} private key installed to {AUTH_PATH}')
        self.logger.info(f'{self.name} ({host}) node installed.')
        create_auth_package()
        self.logger.info(f'Authentication package generated successfully. Copy \'{self.name}.tar.gz\' to {host} and '
                         f'install via \'sudo dynamite remote install {self.name}.tar.gz\'.')
        return self

    def invoke_command(self, *dynamite_arguments, run_as_task: Optional[bool] = False) -> None:
        """ Run a dynamite-nsm cmd compatible command for example: `elasticsearch install --port 8080`
        Args:
            *dynamite_arguments: A list of dynamite-nsm cmd compatible commands.

        Returns: None
        """
        metadata = self.get_metadata()
        time.sleep(1)
        node_obj = db.db_session.query(models.Node).filter(models.Node.host == metadata.host).first()
        node_obj.invoke_count = models.Node.invoke_count + 1
        node_obj.last_invoked_at = datetime.datetime.utcnow()
        db.db_session.commit()

        if run_as_task:
            new_task_directory = f'{os.environ.get("HOME")}/.dynamite_remote/tasks/{int(time.time())}'
            self.logger.info(f'Running in daemon mode.')
            self.logger.debug(f'Task Directory: {new_task_directory}')
            utilities.makedirs(new_task_directory)
            output_logs = open(f'{new_task_directory}/output.log', 'w+')
            with open(f'{new_task_directory}/command', 'w') as command_out:
                command_out.write(' '.join(dynamite_arguments))
            with daemon.DaemonContext(detach_process=True,
                                      pidfile=daemon.pidfile.PIDLockFile(f'{new_task_directory}/task.pid'),
                                      stdout=output_logs,
                                      stderr=output_logs,
                                      ):
                utilities.execute_dynamite_command_on_remote_host(metadata.host, metadata.port, self.key_path,
                                                                  *dynamite_arguments)

            output_logs.close()
        else:
            self.logger.info('Running in foreground.')
            try:
                utilities.execute_dynamite_command_on_remote_host(metadata.host, metadata.port, self.key_path,
                                                                  *dynamite_arguments)
            except utilities.NodeLocked as e:
                self.logger.error(f'{str(e).strip()}. You may use --force if you want to bypass this lock and '
                                  f'execute this command anyway.')

    def remove_execute_lock(self):
        metadata = self.get_metadata()
        lockfile_path = f'{utilities.LOCK_PATH}/{metadata.host}'
        self.logger.info(f'Removing lock: {lockfile_path}')
        utilities.safely_remove_file(lockfile_path)
