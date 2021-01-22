import os
import re
import time
import json
import shutil
import multiprocessing
try:
    from gevent.subprocess import Popen, PIPE
except ImportError:
    from subprocess import PIPE, Popen

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base import logs
from dynamite_nsm.services.zeek import config

REPLAY_ROOT = os.path.join(const.CONFIG_PATH, 'replays', 'zeek')


def list_zeek_replay_ids():
    """
    Get all the pcaps that have been analyzed on this system by id

    :return: A list o replay_ids
    """
    return [f for f in os.listdir(REPLAY_ROOT) if f.isalnum() and len(f) == 32]


def check_replay_exists(pcap_replay_id):
    """
    :param pcap_replay_id: The MD5 hash of the pcap to lookup
    :return: True, if the pcap has already been analyzed.
    """
    return pcap_replay_id in list_zeek_replay_ids()


class ZeekReplay:

    def __init__(self, pcap_replay_id, max_log_size=50000):
        """
        :param pcap_replay_id: The MD5 hash of the pcap being analyzed
        :param max_log_size: The maximum number of entries to keep in memory per log file (E.G if there are a million
                             entries and the max_log_size is 50,000, lines 950,000 - 1,000,000 would be the only
                             iterable entries in that log)
        """
        self.max_log_size = max_log_size
        self.pcap_replay_id = pcap_replay_id
        self.name = None
        self.description = None
        self.analysis_time = None
        self.log_names = []
        self.log_files = {}
        self.analysis_sessions = []
        self.replay_session = os.path.join(REPLAY_ROOT, str(pcap_replay_id))
        self._attach_to_session()

    def __str__(self):
        return json.dumps(dict(replay_id=self.pcap_replay_id, logs=self.log_names))

    def _attach_to_session(self):
        """
        Loads up the contents of a session directory for ready access
        """
        self.log_names = [log.replace('.log', '') for log in os.listdir(self.replay_session) if log.endswith('.log')]
        for log_name in self.log_names:
            self.log_files[log_name] = logs.LogFile(os.path.join(self.replay_session, log_name + '.log'),
                                                    log_sample_size=self.max_log_size)
        with open(os.path.join(self.replay_session, '.metadata'), 'r') as meta_f:
            for analysis_session in meta_f.readlines():
                self.analysis_sessions.append(analysis_session)

        metadata = json.loads(self.analysis_sessions[-1])
        self.name = metadata.get('name')
        self.description = metadata.get('description')
        self.analysis_time = metadata.get('time')

    @classmethod
    def analyze(cls, pcap_path, name=None, description=None, keep_pcap=True):
        """
        Given a PCAP path on disk; analyze that pcap with Zeek storing the results in a directory
        deterministically identified by hashing the pcap file.

        :param pcap_path: The path to the pcap file on disk
        :param name: The name of the pcap (short descriptor)
        :param description: A long description for the pcap
        :param keep_pcap: If True, we'll save a copy of the pcap to disk after analysis
        :return: A ZeekReplay instance
        """
        if name:
            name = re.sub("[^0-9a-zA-Z]+", "", name)[0:64]
        if description:
            description = description[0: 1024]
        environment_variables = utilities.get_environment_file_dict()
        install_directory = environment_variables.get('ZEEK_HOME')
        scripts_directory = environment_variables.get('ZEEK_SCRIPTS')
        pcap_replay_id = utilities.get_filepath_md5_hash(pcap_path)
        replay_session = os.path.join(REPLAY_ROOT, str(pcap_replay_id))
        utilities.makedirs(replay_session)
        zeek_bin_path = os.path.join(install_directory, 'bin', 'zeek')
        zeek_scripts_config = config.ScriptConfigManager(scripts_directory)
        command = 'cd {}; {} -r {} {} -C'.format(replay_session, zeek_bin_path, pcap_path,
                                                 ' '.join(zeek_scripts_config.list_enabled_scripts()))
        child = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
        child.communicate()

        # Write our metadata to disk
        with open(os.path.join(replay_session, '.metadata'), 'a') as meta_f:
            meta_f.write(
                json.dumps({'time': time.time(), 'name': name, 'description': description}) + '\n'
            )

        # Copy over the pcap if we want to keep it.
        if keep_pcap:
            shutil.copy(pcap_path, os.path.join(replay_session, pcap_replay_id + '.pcap'))

        return cls(pcap_replay_id)

    @staticmethod
    def analyze_in_background(pcap_path, name=None, description=None, keep_pcap=True):
        """
        Same as analysis but run as a non-blocking process

        :param pcap_path: The path to the pcap file on disk
        :param name: The name of the pcap (short descriptor)
        :param description: A long description for the pcap
        :param keep_pcap: If True, we'll save a copy of the pcap to disk after analysis
        :return: The replay_id of the pcap being analyzed
        """

        pcap_replay_id = utilities.get_filepath_md5_hash(pcap_path)
        multiprocessing.Process(target=ZeekReplay.analyze, args=(pcap_path, name, description, keep_pcap)).start()
        return pcap_replay_id

    def iter_log(self, log_name='conn'):
        """
        Provides a generator interface for iterating through Zeek logs

        :param log_name: The name of the Zeek log to access
        :return: JSON serializable log entry object
        """
        log_file_obj = self.log_files.get(log_name)
        if not log_file_obj:
            return
        for raw in log_file_obj.iter_cache():
            yield json.loads(raw)

    def get_pcap(self):
        """
        Returns a fileobj in rb mode for the pcap analyzed pcap file, if the keep_pcap flag was set during analysis.
        Be sure to close this handle!

        :return: A fileobj to the pcap file
        """
        try:
            pcap_fh = open(os.path.join(self.replay_session, self.pcap_replay_id + '.pcap'), 'rb')
            return pcap_fh
        except IOError:
            return None
