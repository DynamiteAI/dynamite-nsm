import os
import sys
import json
import time
import signal
import shutil
import tarfile
import subprocess
from multiprocessing import Process

from lib import zeek
from lib import const
from lib import utilities

INSTALL_DIRECTORY = '/opt/dynamite/filebeat/'


class FileBeatConfigurator:

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        self.install_directory = install_directory
        self.agent_tag = None
        self.logstash_targets = None
        self.monitor_target_paths = None
        self._parse_filebeatyaml()

    def _parse_filebeatyaml(self):
        for line in open(os.path.join(self.install_directory, 'filebeat.yml')).readlines():
            if not line.startswith('#') and ':' in line:
                if '"originating_agent_tag"' in line.strip():
                    self.agent_tag = line.split(':')[2].strip()[1:-2]
                elif 'hosts:' in line:
                    self.logstash_targets = list(json.loads(line.replace('hosts:', '').strip()))
                elif 'paths:' in line:
                    self.monitor_target_paths = list(json.loads(line.replace('paths:', '')))

    def set_agent_tag(self, agent_tag):
        """
        Create a tag to associate events/entities with the originating agent

        :param agent_tag: A tag associated with the agent
        """
        self.agent_tag = agent_tag

    def set_logstash_targets(self, target_hosts):
        """
        Define where events should be sent

        :param target_hosts: A list of Logstash hosts, and their service port (E.G ["192.168.0.9:5044"]
        """
        self.logstash_targets = target_hosts

    def set_monitor_target_paths(self, monitor_log_paths):
        """
        Define which logs to monitor and send to Logstash hosts

        :param monitor_log_paths: A list of log files to monitor (wild card '*' accepted)
        """
        self.monitor_target_paths = monitor_log_paths

    def get_agent_tag(self):
        """
        Get the tag associated to the agent
        :return: A tag associated with the agent
        """
        return self.agent_tag

    def get_logstash_targets(self):
        """
        A list of Logstash targets that the agent is pointing too

        :return: A list of Logstash hosts, and their service port (E.G ["192.168.0.9:5044"]
        """
        return self.logstash_targets

    def get_monitor_target_paths(self):
        """
        A list of log paths to monitor

        :return: A list of log files to monitor
        """
        return self.monitor_target_paths

    def write_config(self):
        config_output = ''
        for line in open(os.path.join(self.install_directory, 'filebeat.yml')).readlines():
            if not line.startswith('#') and ':' in line:
                if 'originating_agent_tag' in line:
                    line = '     fields: ["originating_agent_tag": "{}"]\n'.format(self.agent_tag)
                elif 'hosts:' in line:
                    line = '   hosts: {}\n'.format(json.dumps(self.logstash_targets))
                elif 'paths:' in line:
                    line = '  paths: {}\n'.format(json.dumps(self.monitor_target_paths))
            config_output += line
        with open(os.path.join(self.install_directory, 'filebeat.yml'), 'w') as out_config:
            out_config.write(config_output)


class FileBeatInstaller:

    def __init__(self, monitor_paths=(zeek.INSTALL_DIRECTORY + 'logs/current/*.log',),
                 install_directory=INSTALL_DIRECTORY):
        self.monitor_paths = list(monitor_paths)
        self.install_directory = install_directory

    @staticmethod
    def download_filebeat(stdout=False):
        """
        Download Filebeat archive

        :param stdout: Print output to console
        """
        for url in open(const.FILE_BEAT_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.FILE_BEAT_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_filebeat(stdout=False):
        """
        Extract Filebeat to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.FILE_BEAT_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            if stdout:
                sys.stdout.write('[+] Complete!\n')
                sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_filebeat(self, stdout=False):
        """
        Creates necessary directory structure, and copies required files, generates a default configuration

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Creating Filebeat install directory.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        if stdout:
            sys.stdout.write('[+] Copying Filebeat to install directory.\n')
        utilities.copytree(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_DIRECTORY_NAME), self.install_directory)
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'filebeat', 'filebeat.yml'),
                    self.install_directory)
        if stdout:
            sys.stdout.write('[+] Building configurations and setting up permissions.\n')
        beats_config = FileBeatConfigurator(self.install_directory)
        beats_config.set_monitor_target_paths(self.monitor_paths)
        beats_config.write_config()
        utilities.set_permissions_of_file(os.path.join(self.install_directory, 'filebeat.yml'),
                                          unix_permissions_integer=501)
        if 'FILEBEAT_HOME' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating FileBeat default script path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo FILEBEAT_HOME="{}" >> /etc/environment'.format(self.install_directory),
                            shell=True)


class FileBeatProfiler:

    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_running = self._is_running()

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] FileBeat installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        filebeat_home = env_dict.get('FILEBEAT_HOME')
        if not filebeat_home:
            if stderr:
                sys.stderr.write('[-] FILEBEAT_HOME installation directory could not be located in /etc/environment.\n')
            return False
        if not os.path.exists(filebeat_home):
            if stderr:
                sys.stderr.write('[-] FILEBEAT_HOME installation directory could not be located on disk at: {}.\n'.format(
                    filebeat_home))
            return False
        filebeat_home_directories_and_files = os.listdir(filebeat_home)
        if 'filebeat' not in filebeat_home_directories_and_files:
            if stderr:
                sys.stderr.write('[-] Could not locate FILEBEAT {}/filebeat binary.\n'.format(filebeat_home))
            return False
        if 'filebeat.yml' not in filebeat_home_directories_and_files:
            if stderr:
                sys.stderr.write('[-] Could not locate FILEBEAT {}/filebeat.yml config.\n'.format(filebeat_home))
            return False
        return True

    @staticmethod
    def _is_running():
        env_dict = utilities.get_environment_file_dict()
        filebeat_home = env_dict.get('FILEBEAT_HOME')
        if filebeat_home:
            return FileBeatProcess(install_directory=filebeat_home).status()['RUNNING']
        return False

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }


class FileBeatProcess:
    """
    An interface for start|stop|status|restart of the Filebeat process
    """
    def __init__(self, install_directory=INSTALL_DIRECTORY):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/filebeat/)
        """
        self.install_directory = install_directory
        self.config = FileBeatConfigurator(self.install_directory)

        if not os.path.exists('/var/run/dynamite/filebeat/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/filebeat/'), shell=True)

        try:
            self.pid = int(open('/var/run/dynamite/filebeat/filebeat.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the Filebeat daemon
        :param stdout: Print output to console
        :return: True if started successfully
        """
        def start_shell_out():
            command = '{}/filebeat -c {}/filebeat.yml & echo $! > /var/run/dynamite/filebeat/filebeat.pid'.format(
                self.config.install_directory, self.config.install_directory)
            subprocess.call(command, shell=True)
        if stdout:
            sys.stdout.write('[+] Starting Filebeat\n')
        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] Filebeat is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting FileBeat on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/filebeat/filebeat.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting FileBeat on PID [{}]\n'.format(retry + 1, self.pid)
                if stdout:
                    sys.stdout.write(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(5)
                else:
                    return True
            except IOError:
                if stdout:
                    sys.stdout.write(start_message)
                retry += 1
                time.sleep(3)
        return False

    def status(self):
        """
        Check the status of the FileBeat process

        :return: A dictionary containing the run status and relevant configuration options
        """
        log_path = os.path.join(self.config.install_directory, 'logs', 'filebeat')

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'LOGS': log_path
        }

    def stop(self, stdout=False):
        """
        Stop the LogStash process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop Filebeat [{}]\n'.format(self.pid))
                if attempts > 3:
                    sig_command = signal.SIGINT
                else:
                    sig_command = signal.SIGTERM
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(1)
                alive = utilities.check_pid(self.pid)
            except Exception as e:
                sys.stderr.write('[-] An error occurred while attempting to stop Filebeat: {}\n'.format(e))
                return False
        return True