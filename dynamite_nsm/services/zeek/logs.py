from __future__ import annotations

import itertools
import json
import os
import time
from datetime import datetime
from datetime import timedelta
from typing import Dict, Generator, Optional

import tabulate

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base import logs


def parse_zeek_datetime(t: str) -> datetime:
    return datetime.utcfromtimestamp(int(str(t).split('.')[0]))


class InvalidZeekStatusLogEntry(Exception):
    """
    Thrown when a Zeek stats.log entry is improperly formatted
    """

    def __init__(self, message):
        """
        Args:
            message: A more specific error message
        """
        msg = f'Zeek status log entry is invalid: {message}'
        super(InvalidZeekStatusLogEntry, self).__init__(msg)


class InvalidZeekBrokerLogEntry(Exception):
    """
    Thrown when a Zeek broker.log entry is improperly formatted
    """

    def __init__(self, message):
        """
        Args:
            message: A more specific error message
        """
        msg = f'Zeek broker log entry is invalid: {message}'
        super(InvalidZeekBrokerLogEntry, self).__init__(msg)


class InvalidZeekClusterLogEntry(Exception):
    """
    Thrown when a Zeek cluster.log entry is improperly formatted
    """

    def __init__(self, message):
        """
        Args:
            message: A more specific error message
        """
        msg = f'Zeek cluster log entry is invalid: {message}'
        super(InvalidZeekClusterLogEntry, self).__init__(msg)


class InvalidZeekReporterLogEntry(Exception):
    """
    Thrown when a Zeek reporter.log entry is improperly formatted
    """

    def __init__(self, message):
        """
        Args:
            message: A more specific error message
        """
        msg = f'Zeek reporter log entry is invalid: {message}'
        super(InvalidZeekReporterLogEntry, self).__init__(msg)


class BrokerEntry:
    """
    A single line item entry for Zeek's broker.log
    """

    def __init__(self, entry_raw: str):
        """
        A single line item entry in the broker.log

        Args:
            entry_raw: A JSON serializable string representing a single line item entry in the broker.log
        """
        self.entry_raw = entry_raw
        self.time = None
        self.timestamp = None
        self.category = None
        self.event = None
        self.peer_address = None
        self.peer_port = None
        self.message = None
        self._parse_entry()

    def _parse_entry(self) -> None:
        log_entry = self.entry_raw.replace("\n", "")
        try:
            entry = json.loads(log_entry)
        except ValueError:
            raise InvalidZeekBrokerLogEntry(
                'broker.log entry is not JSON formatted. '
                'Make sure to enable policy/tuning/json-logs is loaded.')
        self.timestamp = entry.get('ts')
        self.category = entry.get('ty')
        self.event = entry.get('ev')
        self.peer_address = entry.get('peer.address')
        self.peer_port = entry.get('peer.bound_port')
        self.message = entry.get('message')
        if not self.timestamp:
            raise InvalidZeekStatusLogEntry('Missing timestamp field')
        self.time = parse_zeek_datetime(self.timestamp)

    def __str__(self) -> str:
        log_entry = dict(
            time=str(self.time),
            category=self.category,
            event=self.event,
            peer_address=self.peer_address,
            peer_port=self.peer_port,
            message=self.message
        )
        return json.dumps(log_entry)


class ClusterEntry:
    """
    A single line item entry for Zeek's cluster.log
    """

    def __init__(self, entry_raw: str):
        """
        A single line item entry in the cluster.log

        Args:
            entry_raw: A JSON serializable string representing a single line item entry in the cluster.log
        """
        self.entry_raw = entry_raw
        self.time = None
        self.timestamp = None
        self.message = None
        self._parse_entry()

    def _parse_entry(self) -> None:
        log_entry = self.entry_raw.replace("\n", "")
        try:
            entry = json.loads(log_entry)
        except ValueError:
            raise InvalidZeekClusterLogEntry(
                'cluster.log entry is not JSON formatted. '
                'Make sure to enable policy/tuning/json-logs is loaded.')
        self.timestamp = entry.get('ts')
        self.node = entry.get('node')
        self.message = entry.get('message')
        if not self.timestamp:
            raise InvalidZeekStatusLogEntry('Missing timestamp field')
        self.time = parse_zeek_datetime(self.timestamp)

    def __str__(self) -> str:
        log_entry = dict(
            time=str(self.time),
            node=self.node,
            message=self.message
        )
        return json.dumps(log_entry)


class MetricsEntry:
    """
    A single Filebeat metrics entry for a specific time-interval
    """

    def __init__(self, entry: Dict):
        """
        A metrics entry derived from the stats.log

        Args:
            entry: A dictionary containing a variety of analyzable fields within a line item metrics entry
        """
        self.entry_raw = entry
        self.timestamp = entry.get('ts')
        self.time = parse_zeek_datetime(self.timestamp)
        self.peer = entry.get('peer')
        self.peers = [self.peer]
        self.memory = entry.get('mem', 0)
        self.packets_processed = entry.get('pkts_proc', 0)
        self.bytes_received = entry.get('bytes_recv', 0)
        self.packets_dropped = entry.get('pkts_dropped', 0)
        self.packets_link = entry.get('pkts_link', 0)
        self.packet_lag = entry.get('pkt_lag', 0)
        self.events_processed = entry.get('events_proc', 0)
        self.events_queued = entry.get('events_queued', 0)
        self.active_tcp_connections = entry.get('active_tcp_conns', 0)
        self.active_udp_connections = entry.get('active_udp_conns', 0)
        self.active_icmp_connections = entry.get('active_icmp_conns', 0)
        self.tcp_connections = entry.get('tcp_conns', 0)
        self.udp_connections = entry.get('udp_conns', 0)
        self.icmp_connections = entry.get('icmp_conns', 0)
        self.timers = entry.get('timers', 0)
        self.files = entry.get('files', 0)
        self.active_files = entry.get('active_files', 0)
        self.dns_requests = entry.get('dns_requests', 0)
        self.active_dns_requests = entry.get('active_dns_requests', 0)
        self.reassembly_tcp_size = entry.get('reassem_tcp_size', 0)
        self.reassembly_file_size = entry.get('reassem_file_size', 0)
        self.reassembly_fragment_size = entry.get('reassem_frag_size', 0)
        self.reassembly_unknown_size = entry.get('reassem_unknown_size', 0)
        self.packets_dropped_percentage = 0
        if self.packets_link > 0:
            self.packets_dropped_percentage = round(self.packets_dropped / self.packets_link, 2)

    def merge_metric_entry(self, metric_entry: MetricsEntry) -> None:
        """Merge another metrics entry into this one
        Args:
            metric_entry: The MetricsEntry you wish to merge in
        Returns:
            None
        """
        self.peer = None
        self.peers.append(metric_entry.peer)
        self.memory = self.memory + metric_entry.memory
        self.packets_processed = self.packets_processed + metric_entry.packets_processed
        self.bytes_received = self.bytes_received + metric_entry.bytes_received
        self.packets_dropped = self.packets_dropped + metric_entry.packets_dropped
        self.packets_link = self.packets_link + metric_entry.packets_link
        self.packet_lag = self.packet_lag + metric_entry.packet_lag
        self.events_processed = self.events_processed + metric_entry.events_processed
        self.events_queued = self.events_queued + metric_entry.events_queued
        self.active_tcp_connections = self.active_tcp_connections + metric_entry.active_tcp_connections
        self.active_udp_connections = self.active_udp_connections + metric_entry.active_udp_connections
        self.active_icmp_connections = self.active_icmp_connections + metric_entry.active_icmp_connections
        self.tcp_connections = self.tcp_connections + metric_entry.tcp_connections
        self.udp_connections = self.udp_connections + metric_entry.udp_connections
        self.icmp_connections = self.icmp_connections + metric_entry.icmp_connections
        self.timers = self.timers + metric_entry.timers
        self.files = self.files + metric_entry.files
        self.active_files = self.active_files + metric_entry.active_files
        self.dns_requests = self.dns_requests + metric_entry.dns_requests
        self.active_dns_requests = self.active_dns_requests + metric_entry.active_dns_requests
        self.reassembly_tcp_size = self.reassembly_tcp_size + metric_entry.reassembly_tcp_size
        self.reassembly_file_size = self.reassembly_file_size + metric_entry.reassembly_file_size
        self.reassembly_fragment_size = self.reassembly_fragment_size + metric_entry.reassembly_fragment_size
        self.reassembly_unknown_size = self.reassembly_unknown_size + metric_entry.reassembly_unknown_size
        if self.packets_processed > 0:
            self.packets_dropped_percentage = round(self.packets_dropped / self.packets_link, 6)

    def __str__(self) -> str:
        return json.dumps(dict(
            timestamp=self.timestamp,
            time=str(self.time),
            peer=self.peer,
            peers=self.peers,
            memory=self.memory,
            packets_processed=self.packets_processed,
            bytes_received=self.bytes_received,
            packets_dropped=self.packets_dropped,
            packets_dropped_percentage=self.packets_dropped_percentage,
            packets_link=self.packets_link,
            packet_lag=self.packet_lag,
            events_processed=self.events_processed,
            events_queued=self.events_queued,
            active_tcp_connections=self.active_tcp_connections,
            active_udp_connections=self.active_udp_connections,
            active_icmp_connections=self.active_icmp_connections,
            tcp_connections=self.tcp_connections,
            udp_connections=self.udp_connections,
            icmp_connections=self.icmp_connections,
            timers=self.timers,
            files=self.files,
            active_files=self.active_files,
            dns_requests=self.dns_requests,
            active_dns_requests=self.active_dns_requests,
            reassembly_tcp_size=self.reassembly_tcp_size,
            reassembly_file_size=self.reassembly_file_size,
            reassembly_fragment_size=self.reassembly_fragment_size,
            reassembly_unknown_size=self.reassembly_unknown_size
        ))


class ReporterEntry:
    """
    A single line item entry for Zeek's reporter.log
    """

    def __init__(self, entry_raw: str):
        """
        A single line item entry in the reporter.log

        Args:
            entry_raw: A JSON serializable string representing a single line item entry in the reporter.log
        """
        self.entry_raw = entry_raw
        self.time = None
        self.timestamp = None
        self.log_level = None
        self.message = None
        self.location = None
        self._parse_entry()

    def _parse_entry(self) -> None:
        log_entry = self.entry_raw.replace("\n", "")
        try:
            entry = json.loads(log_entry)
        except ValueError:
            raise InvalidZeekReporterLogEntry(
                'reporter.log entry is not JSON formatted. '
                'Make sure to enable policy/tuning/json-logs is loaded.')
        self.timestamp = entry.get('ts')
        self.log_level = entry.get('level')
        self.location = entry.get('location')
        self.message = entry.get('message')
        if not self.timestamp:
            raise InvalidZeekReporterLogEntry('Missing timestamp field')
        if self.log_level:
            self.log_level = str(self.log_level.replace('Reporter::', ''))
        self.time = parse_zeek_datetime(self.timestamp)

    def __str__(self) -> str:
        log_entry = dict(
            time=str(self.time),
            log_level=self.log_level,
            location=self.location,
            message=self.message
        )
        return json.dumps(log_entry)


class ZeekLogsProxy:
    """
    A convenience class providing accessibility to Zeek's archived logs; supports gzipped content
    """

    def __init__(self, log_name: str, log_sample_size: Optional[int] = 1000):
        """Access a log and all of its corresponding archived logs until log_sample_size is reached.
        Args:
            log_name: The name of the Zeek log to retrieve
            log_sample_size: The max number of log entries to retrieve
        """
        self.entries = []
        self.log_name = log_name
        self.log_sample_size = log_sample_size
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.zeek_home = self.env_dict.get('ZEEK_HOME')
        self.current_log_path = os.path.join(self.zeek_home, 'logs', 'current', log_name)
        self.log_archive_directory = os.path.join(self.zeek_home, 'logs')
        self.load_all_logs()

    def load_all_logs(self) -> None:
        """
        Load all logs into memory up to self.log_sample_size
        
        Returns:
            None
        """
        archive_directories = []
        sorted_log_paths = []
        for log_archive_directory in os.listdir(self.log_archive_directory):
            try:
                archive_directories.append(
                    (log_archive_directory, datetime.strptime(log_archive_directory, '%Y-%m-%d')))
            except ValueError:
                pass
        sorted_archive_directories = sorted(archive_directories, key=lambda x: x[1])

        for archive_dir_name, _ in sorted_archive_directories:
            relevant_log_names = [fname
                                  for fname in os.listdir(os.path.join(self.log_archive_directory, archive_dir_name))
                                  if fname.startswith(self.log_name.replace('.log', '')) and fname.endswith('.gz')
                                  ]
            for log_archive_file_name in relevant_log_names:
                log_rotate_time = log_archive_file_name.split('.')[1].split('-')[0]
                sorted_log_paths.append(
                    (os.path.join(self.log_archive_directory, archive_dir_name, log_archive_file_name),
                     datetime.strptime(archive_dir_name + ' ' + log_rotate_time, '%Y-%m-%d %H:%M:%S'))
                )
            sorted_log_paths = sorted(sorted_log_paths, key=lambda x: x[1], reverse=True)

        current_log_file = logs.LogFile(log_path=self.current_log_path, log_sample_size=self.log_sample_size,
                                        gzip_decode=False)
        self.entries.extend(current_log_file.entries)
        for log_path, log_rotate_date in sorted_log_paths:
            archived_log_file = logs.LogFile(log_path, log_sample_size=self.log_sample_size, gzip_decode=True)
            remaining_entries_available = self.log_sample_size - len(self.entries)
            if remaining_entries_available > 0:
                self.entries.extend(archived_log_file.entries[0: remaining_entries_available])
            else:
                break

    def iter_entries(self) -> Generator[str]:
        for log_entry in self.entries:
            yield log_entry


class BrokerLog(logs.LogFile):
    """
    Provides an interface for working with Zeek's broker.log
    """

    def __init__(self, log_sample_size: Optional[int] = 500, include_archived_logs: Optional[bool] = False):
        """
        Work with Zeek's broker.log

        Args:
            log_sample_size: The maximum number of log entries to load into memory
            include_archived_logs: If True, include gzipped archive logs
        """
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.zeek_home = self.env_dict.get('ZEEK_HOME')
        self.log_path = os.path.join(self.zeek_home, 'logs', 'current', 'broker.log')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)
        if include_archived_logs:
            self.entries = ZeekLogsProxy('broker.log', log_sample_size=log_sample_size).entries

    def iter_entries(self, start: Optional[datetime] = None, end: Optional[datetime] = None) -> Generator[BrokerEntry]:
        """Iterate through BrokerEntries while providing some basic filtering options
        Args:
            start: UTC start time
            end: UTC end time
        Returns:
             yields a BrokerEntry for every iteration
        """

        def filter_entries(s: Optional[datetime], e: Optional[datetime] = None):
            if not e:
                e = datetime.utcnow()
            if not s:
                s = datetime.utcnow() - timedelta(days=365)
            for en in self.entries:
                en = BrokerEntry(en)
                if s < en.time < e:
                    yield en

        for log_entry in filter_entries(start, end):
            yield log_entry

    def tail(self, pretty_print: Optional[bool] = True) -> None:
        """Tail and follow a log to console
        Args:
            pretty_print: Print the log entry in a nice tabular view
        Returns:
            None
        """
        visited = []
        start = datetime.utcnow() - timedelta(days=365)
        try:
            while True:
                end = datetime.utcnow()
                self.refresh()
                for entry in self.iter_entries(start=start, end=end):
                    if entry.timestamp not in visited:
                        visited.append(entry.timestamp)
                        if not pretty_print:
                            print(json.dumps(json.loads(str(entry)), indent=1))
                        else:
                            status_table = [
                                ['Time', 'Category', 'Peer', 'Message'],
                                [entry.time, entry.category, f'{entry.peer_address}:{entry.peer_port}', entry.message]
                            ]
                            print(tabulate.tabulate(status_table, tablefmt='fancy_grid'))
                    if len(visited) > 100:
                        visited = []
                start = datetime.utcnow() - timedelta(seconds=60)
                time.sleep(5)
        except KeyboardInterrupt:
            print(utilities.PrintDecorations.colorize('OK', 'green'))


class ClusterLog(logs.LogFile):
    """
    Provides an interface for working with Zeek's cluster.log
    """

    def __init__(self, log_sample_size: Optional[int] = 500, include_archived_logs: Optional[bool] = False):
        """Work with Zeek's cluster.log
            log_sample_size: The maximum number of log entries to load into memory
            include_archived_logs: If True, include gzipped archive logs
        """
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.zeek_home = self.env_dict.get('ZEEK_HOME')
        self.log_path = os.path.join(self.zeek_home, 'logs', 'current', 'cluster.log')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)
        if include_archived_logs:
            self.entries = ZeekLogsProxy('cluster.log', log_sample_size=log_sample_size).entries

    def iter_entries(self, start: Optional[datetime] = None, end: Optional[datetime] = None) -> Generator[ClusterEntry]:
        """Iterate through ClusterEntries while providing some basic filtering options
        Args:
            start: UTC start time
            end: UTC end time
        Returns:
             yields a ClusterEntry for every iteration
        """

        def filter_entries(s: Optional[datetime], e: Optional[datetime] = None):
            if not e:
                e = datetime.utcnow()
            if not s:
                s = datetime.utcnow() - timedelta(days=365)
            for en in self.entries:
                en = ClusterEntry(en)
                if s < en.time < e:
                    yield en

        for log_entry in filter_entries(start, end):
            yield log_entry

    def tail(self, pretty_print: Optional[bool] = True) -> None:
        """Tail and follow a log to console
        Args:
            pretty_print: Print the log entry in a nice tabular view
        Returns:
            None
        """
        visited = []
        start = datetime.utcnow() - timedelta(days=365)
        try:
            while True:
                end = datetime.utcnow()
                self.refresh()
                for entry in self.iter_entries(start=start, end=end):
                    if entry.timestamp not in visited:
                        visited.append(entry.timestamp)
                        if not pretty_print:
                            print(json.dumps(json.loads(str(entry)), indent=1))
                        else:
                            status_table = [
                                ['Time', 'Node', 'Message'],
                                [entry.time, entry.node, entry.message]
                            ]
                            print(tabulate.tabulate(status_table, tablefmt='fancy_grid'))
                    if len(visited) > 100:
                        visited = []
                start = datetime.utcnow() - timedelta(seconds=60)
                time.sleep(5)
        except KeyboardInterrupt:
            print(utilities.PrintDecorations.colorize('OK', 'green'))


class StatusLog(logs.LogFile):
    """
    Provides an interface for working with Zeek's stats.log
    """

    def __init__(self, log_sample_size: Optional[int] = 500, include_archived_logs: Optional[bool] = False):
        """Work with Zeek's stats.log
        Args:
            log_sample_size: The maximum number of log entries to load into memory
            include_archived_logs: If True, include gzipped archive logs content
        """

        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.zeek_home = self.env_dict.get('ZEEK_HOME')
        self.log_path = os.path.join(self.zeek_home, 'logs', 'current', 'stats.log')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)
        if include_archived_logs:
            self.entries = ZeekLogsProxy('stats.log', log_sample_size=log_sample_size).entries

    def iter_metrics(self, start: Optional[datetime] = None, end: Optional[datetime] = None) -> Generator[MetricsEntry]:
        """Iterate through metrics entries individually. Metrics are given for each individual Zeek peer.

        Args:
            start: UTC start time
            end: UTC end time
        Returns:
             yields a MetricsEntry for every iteration
        """

        def filter_metrics(s: Optional[datetime] = None, e: Optional[datetime] = None):
            if not e:
                e = datetime.utcnow()
            if not s:
                s = datetime.utcnow() - timedelta(minutes=60)
            for en in self.entries:
                en = MetricsEntry(json.loads(en))
                if s < en.time < e:
                    yield en

        for log_entry in filter_metrics(start, end):
            yield log_entry

    def iter_aggregated_metrics(self, start: Optional[datetime] = None, end: Optional[datetime] = None,
                                tolerance_seconds: Optional[int] = 60) -> Generator[MetricsEntry]:

        """Aggregate peers and combine events within tolerance_seconds into the same entry.

        Args:
            start: UTC start time
            end: UTC end time
            tolerance_seconds: Specifies the maximum time distance between entries to combine them
        Returns:
             yields a MetricsEntry for every iteration
        """
        sorted_by_time = [metric for metric in self.iter_metrics(start, end)]
        if not sorted_by_time:
            return
        sorted_by_time = sorted(sorted_by_time, key=lambda x: x.timestamp)
        start = sorted_by_time[0].time
        for name, group in itertools.groupby(
                sorted_by_time, lambda x: int((x.time - start).total_seconds() // tolerance_seconds + 1)):
            aggregated_entry = None
            for entry in group:
                if not aggregated_entry:
                    aggregated_entry = entry
                else:
                    aggregated_entry.merge_metric_entry(entry)
            yield aggregated_entry

    def tail(self, pretty_print: Optional[bool] = True) -> None:
        """Tail and follow a log to console
        Args:
            pretty_print: Print the log entry in a nice tabular view
        Returns:
            None
        """
        visited = []
        start = datetime.utcnow() - timedelta(days=365)
        try:
            while True:
                end = datetime.utcnow()
                self.refresh()
                for metric in self.iter_aggregated_metrics(start=start, end=end):
                    if metric.timestamp not in visited:
                        visited.append(metric.timestamp)
                        if not pretty_print:
                            print(json.dumps(json.loads(str(metric)), indent=1))
                        else:
                            status_table = [
                                ['Time', 'Memory', 'Timers', 'Packets on Link', 'Packets Processed', 'Packets Dropped',
                                 'Peers'],
                                [metric.time, metric.memory, metric.timers, metric.packets_link,
                                 metric.packets_processed, metric.packets_dropped, '\n'.join(metric.peers)]
                            ]
                            print(tabulate.tabulate(status_table, tablefmt='fancy_grid'))
                    if len(visited) > 100:
                        visited = []
                start = datetime.utcnow() - timedelta(seconds=60)
                time.sleep(5)
        except KeyboardInterrupt:
            print(utilities.PrintDecorations.colorize('OK', 'green'))


class ReporterLog(logs.LogFile):
    """
    Provides an interface for working with Zeek's reporter.log
    """

    def __init__(self, log_sample_size: Optional[int] = 500, include_archived_logs: Optional[bool] = False):
        """Work with Zeek's reporter.log
        Args:
            log_sample_size: The maximum number of log entries to load into memory
            include_archived_logs: If True, include gzipped archive logs content
        """

        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.zeek_home = self.env_dict.get('ZEEK_HOME')
        self.log_path = os.path.join(self.zeek_home, 'logs', 'current', 'reporter.log')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)
        if include_archived_logs:
            self.entries = ZeekLogsProxy('reporter.log', log_sample_size=log_sample_size).entries

    def iter_entries(self, start: Optional[datetime] = None,
                     end: Optional[datetime] = None) -> Generator[ReporterEntry]:
        """Iterate through ReporterEntries while providing some basic filtering options
        Args:
            start: UTC start time
            end: UTC end time
        Returns:
             yields a ReporterEntry for every iteration
        """

        def filter_entries(s: Optional[datetime], e: Optional[datetime] = None):
            if not e:
                e = datetime.utcnow()
            if not s:
                s = datetime.utcnow() - timedelta(days=365)
            for en in self.entries:
                en = ReporterEntry(en)
                if s < en.time < e:
                    yield en

        for log_entry in filter_entries(start, end):
            yield log_entry

    def tail(self, pretty_print: Optional[bool] = True) -> None:
        """Tail and follow a log to console
        Args:
            pretty_print: Print the log entry in a nice tabular view
        Returns:
            None
        """
        visited = []
        start = datetime.utcnow() - timedelta(days=365)
        try:
            while True:
                end = datetime.utcnow()
                self.refresh()
                for entry in self.iter_entries(start=start, end=end):
                    if entry.timestamp not in visited:
                        visited.append(entry.timestamp)
                        if not pretty_print:
                            print(json.dumps(json.loads(str(entry)), indent=1))
                        else:
                            status_table = [
                                ['Time', 'Log Level', 'Location', 'Message'],
                                [entry.time, entry.log_level, entry.location, entry.message]
                            ]
                            print(tabulate.tabulate(status_table, tablefmt='fancy_grid'))
                    if len(visited) > 100:
                        visited = []
                start = datetime.utcnow() - timedelta(seconds=60)
                time.sleep(5)
        except KeyboardInterrupt:
            print(utilities.PrintDecorations.colorize('OK', 'green'))
