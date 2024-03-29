import itertools
import json
import math
import os
import time
from datetime import datetime
from datetime import timedelta
from typing import Dict, Generator, Optional

import tabulate

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base import logs


class InvalidSuricataStatusLogEntry(ValueError):
    """
    Thrown when a Suricata suricata.log entry is improperly formatted
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "Suricata log entry is invalid: {}".format(message)
        super(InvalidSuricataStatusLogEntry, self).__init__(msg)


def parse_suricata_datetime(t: str) -> datetime:
    """
    Parse a common suricata timestamp string

    Args:
        t: A '%Y-%m-%dT%H:%M:%S.%f' formatted string

    Returns: A datetime object

    """
    ret = datetime.strptime(t[0:22], '%Y-%m-%dT%H:%M:%S.%f')
    if t[26] == '+':
        ret -= timedelta(hours=int(t[27:29]), minutes=int(t[30:]))
    elif t[26] == '-':
        ret += timedelta(hours=int(t[27:29]), minutes=int(t[30:]))
    return ret


class MainEntry:
    """
    A single line item entry in suricata.log
    """
    LOG_LEVEL_MAP = dict(
        Debug="DEBUG",
        Info="INFO",
        Notice="NOTICE",
        Warning="WARN",
        Error="ERROR",
        Critical="CRITICAL"
    )

    def __init__(self, entry_raw: str):
        """
        A single line item entry in the suricata.log

        Args:
            entry_raw: A JSON serializable string representing a single line item entry in the suricata.log
        """

        self.entry_raw = entry_raw
        self.time = None
        self.timestamp = None
        self.log_level = None
        self.category = None
        self.error_code = None
        self.error = None
        self.message = None
        self._parse_entry()

    def _parse_entry(self):
        log_entry = self.entry_raw.replace("\n", "")
        try:
            entry = json.loads(log_entry)
        except ValueError:
            raise InvalidSuricataStatusLogEntry(
                'suricata.log entry is not JSON formatted. '
                'Make sure to enable logging.file.type="json" in suricata.yaml.')
        self.timestamp = entry.get('timestamp')
        self.log_level = entry.get('log_level')
        self.category = entry.get('event_type')
        self.error_code = entry.get('engine', {}).get('error_code', 0)
        self.error = entry.get('engine', {}).get('error', None)
        self.message = entry.get('engine', {}).get('message', None)
        if not self.timestamp:
            raise InvalidSuricataStatusLogEntry('Missing timestamp field')
        if self.log_level:
            self.log_level = self.LOG_LEVEL_MAP.get(self.log_level)
        self.time = parse_suricata_datetime(self.timestamp)

    def __str__(self):
        log_entry = dict(
            time=str(self.time),
            log_level=self.log_level,
            category=self.category,
            error_code=self.error_code,
            error=self.error,
            message=self.message,
        )
        return json.dumps(log_entry)


class MetricsEntry:
    """
    A single Suricata stats.log (or eve.json "stats") metric entry
    """
    def __init__(self, time: str, uptime: str, capture_kernel_packets: int, capture_kernel_drops: int,
                 capture_errors: int,
                 flow_memory: int, tcp_memory: int, tcp_reassembly_memory: int, dns_memory: int, http_memory: int,
                 ftp_memory: int, http_events: int,
                 tls_events: int, ssh_events: int, imap_events: int, msn_events: int, smb_events: int,
                 dcerpc_tcp_events: int, dns_tcp_events: int,
                 nfs_tcp_events: int, ntp_events: int, ftp_data_events: int, tftp_events: int, ikev2_data_events: int,
                 krb5_tcp_events: int,
                 dhcp_events: int, failed_tcp_events: int, dcerpc_udp_events: int, dns_udp_events: int,
                 krb5_udp_events: int, failed_udp_events: int):
        """
        A metrics entry

        Args:
            time: A string representing the time the metric was generated by Suricata
            uptime: The amount of time suricata has been up
            capture_kernel_packets: The number of packets the kernel has seen
            capture_kernel_drops: The number of packets the kernel has dropped
            capture_errors: Errors seen while acquiring packet
            flow_memory: Memory (bytes) utilized for parsing flows
            tcp_memory: Memory (bytes) utilized for TCP parsing
            tcp_reassembly_memory: Memory (bytes) utilized for TCP stream reassembly
            dns_memory: Memory (bytes) utilized for parsing DNS related traffic
            http_memory: Memory (bytes) utilized for parsing HTTP related traffic
            ftp_memory: Memory (bytes) utilized for parsing FTP related traffic
            http_events: An internal Suricata event metric (useful for debugging)
            tls_events: An internal Suricata event metric (useful for debugging)
            ssh_events: An internal Suricata event metric (useful for debugging)
            imap_events: An internal Suricata event metric (useful for debugging)
            msn_events: An internal Suricata event metric (useful for debugging)
            smb_events: An internal Suricata event metric (useful for debugging)
            dcerpc_tcp_events: An internal Suricata event metric (useful for debugging)
            dns_tcp_events: An internal Suricata event metric (useful for debugging)
            nfs_tcp_events: An internal Suricata event metric (useful for debugging)
            ntp_events: An internal Suricata event metric (useful for debugging)
            ftp_data_events: An internal Suricata event metric (useful for debugging)
            tftp_events: An internal Suricata event metric (useful for debugging)
            ikev2_data_events: An internal Suricata event metric (useful for debugging)
            krb5_tcp_events: An internal Suricata event metric (useful for debugging)
            dhcp_events: An internal Suricata event metric (useful for debugging)
            failed_tcp_events: An internal Suricata event metric (useful for debugging)
            dcerpc_udp_events: An internal Suricata event metric (useful for debugging)
            dns_udp_events: An internal Suricata event metric (useful for debugging)
            krb5_udp_events: An internal Suricata event metric (useful for debugging)
            failed_udp_events: An internal Suricata event metric (useful for debugging)
        """

        self.timestamp = str(time)
        self.time = time
        self.uptime = uptime
        self.capture_kernel_packets = capture_kernel_packets
        self.capture_kernel_drops = capture_kernel_drops
        self.capture_errors = capture_errors
        self.flow_memory = flow_memory
        self.tcp_memory = tcp_memory
        self.tcp_reassembly_memory = tcp_reassembly_memory
        self.dns_memory = dns_memory
        self.http_memory = http_memory
        self.ftp_memory = ftp_memory
        self.http_events = http_events
        self.tls_events = tls_events
        self.ssh_events = ssh_events
        self.imap_events = imap_events
        self.msn_events = msn_events
        self.smb_events = smb_events
        self.dcerpc_tcp_events = dcerpc_tcp_events
        self.dns_tcp_events = dns_tcp_events
        self.nfs_tcp_events = nfs_tcp_events
        self.ntp_events = ntp_events
        self.ftp_data_events = ftp_data_events
        self.tftp_events = tftp_events
        self.ikev2_data_events = ikev2_data_events
        self.krb5_tcp_events = krb5_tcp_events
        self.dhcp_events = dhcp_events
        self.failed_tcp_events = failed_tcp_events
        self.dcerpc_udp_events = dcerpc_udp_events
        self.dns_udp_events = dns_udp_events
        self.krb5_udp_events = krb5_udp_events
        self.failed_udp_events = failed_udp_events
        self.capture_kernel_drops_percentage = 0
        if self.capture_kernel_packets > 0:
            self.capture_kernel_drops_percentage = round(self.capture_kernel_drops / self.capture_kernel_packets, 2)

    @classmethod
    def create_from_raw_stats_entry(cls, entry_raw_stats: Dict):
        """
        Create a metrics entry from stats.log serialized entry.

        Args:
            entry_raw_stats: A dictionary containing the various metrics fields found in stats.log.

        Returns: An instance of MetricsEntry class
        """
        entry_raw = entry_raw_stats
        time = entry_raw.get('time')
        uptime = entry_raw.get('uptime')
        capture_kernel_packets = entry_raw.get('capture.kernel_packets', 0)
        capture_kernel_drops = entry_raw.get('capture.kernel_drops', 0)
        capture_errors = entry_raw.get('capture.errors', 0)
        flow_memory = entry_raw.get('flow.memuse', 0)
        tcp_memory = entry_raw.get('tcp.memuse', 0)
        tcp_reassembly_memory = entry_raw.get('tcp.reassembly_memuse', 0)
        dns_memory = entry_raw.get('dns.memuse', 0)
        http_memory = entry_raw.get('http.memuse', 0)
        ftp_memory = entry_raw.get('ftp.memuse', 0)
        http_events = entry_raw.get('app_layer.flow.http', 0)
        tls_events = entry_raw.get('app_layer.flow.tls', 0)
        ssh_events = entry_raw.get('app_layer.flow.ssh', 0)
        imap_events = entry_raw.get('app_layer.flow.imap', 0)
        msn_events = entry_raw.get('app_layer.flow.msn', 0)
        smb_events = entry_raw.get('app_layer.flow.smb', 0)
        dcerpc_tcp_events = entry_raw.get('app_layer.flow.dcerpc_tcp', 0)
        dns_tcp_events = entry_raw.get('app_layer.flow.dns_tcp', 0)
        nfs_tcp_events = entry_raw.get('app_layer.flow.nfs_tcp', 0)
        ntp_events = entry_raw.get('app_layer.flow.dcerpc_tcp', 0)
        ftp_data_events = entry_raw.get('app_layer.flow.ftp-data', 0)
        tftp_events = entry_raw.get('app_layer.flow.tftp', 0)
        ikev2_data_events = entry_raw.get('app_layer.flow.ikev2', 0)
        krb5_tcp_events = entry_raw.get('app_layer.flow.krb5_tcp', 0)
        dhcp_events = entry_raw.get('app_layer.flow.dhcp', 0)
        failed_tcp_events = entry_raw.get('app_layer.flow.failed_tcp', 0)
        dcerpc_udp_events = entry_raw.get('app_layer.flow.failed_udp', 0)
        dns_udp_events = entry_raw.get('app_layer.flow.dns_udp', 0)
        krb5_udp_events = entry_raw.get('app_layer.flow.krb5_udp', 0)
        failed_udp_events = entry_raw.get('app_layer.flow.failed_udp', 0)

        return cls(time, uptime, capture_kernel_packets, capture_kernel_drops, capture_errors,
                   flow_memory, tcp_memory, tcp_reassembly_memory, dns_memory, http_memory, ftp_memory, http_events,
                   tls_events, ssh_events, imap_events, msn_events, smb_events, dcerpc_tcp_events, dns_tcp_events,
                   nfs_tcp_events, ntp_events, ftp_data_events, tftp_events, ikev2_data_events, krb5_tcp_events,
                   dhcp_events, failed_tcp_events, dcerpc_udp_events, dns_udp_events, krb5_udp_events,
                   failed_udp_events)

    @classmethod
    def create_from_eve_raw_stats(cls, entry_raw_eve):
        """
        Create a metrics entry from stats.log serialized entry.

        Args:
            entry_raw_eve: A dictionary containing the various metrics fields found in eve.json `stats` entry

        Returns: An instance of MetricsEntry class
        """
        entry_raw = entry_raw_eve
        stats = entry_raw['stats']
        timestamp = entry_raw.get('timestamp')
        time = parse_suricata_datetime(timestamp)
        uptime = stats.get('uptime')
        capture_kernel_packets = stats.get('capture', {}).get('kernel_packets', 0)
        capture_kernel_drops = stats.get('capture', {}).get('kernel_drops', 0)
        capture_errors = stats.get('capture', {}).get('errors', 0)
        flow_memory = stats.get('flow', {}).get('memuse', 0)
        tcp_memory = stats.get('tcp', {}).get('memuse', 0)
        tcp_reassembly_memory = stats.get('tcp', {}).get('reassembly_memuse', 0)
        dns_memory = stats.get('dns', {}).get('memuse', 0)
        http_memory = stats.get('http', {}).get('memuse', 0)
        ftp_memory = stats.get('ftp', {}).get('memuse', 0)
        http_events = stats.get('app_layer', {}).get('flow', {}).get('http', 0)
        tls_events = stats.get('app_layer', {}).get('flow', {}).get('tls', 0)
        ssh_events = stats.get('app_layer', {}).get('flow', {}).get('ssh', 0)
        imap_events = stats.get('app_layer', {}).get('flow', {}).get('imap', 0)
        msn_events = stats.get('app_layer', {}).get('flow', {}).get('msn', 0)
        smb_events = stats.get('app_layer', {}).get('flow', {}).get('smb', 0)
        dcerpc_tcp_events = stats.get('app_layer', {}).get('flow', {}).get('dcerpc_tcp', 0)
        dns_tcp_events = stats.get('app_layer', {}).get('flow', {}).get('dns_tcp', 0)
        nfs_tcp_events = stats.get('app_layer', {}).get('flow', {}).get('nfs_tcp', 0)
        ntp_events = stats.get('app_layer', {}).get('flow', {}).get('ntp', 0)
        ftp_data_events = stats.get('app_layer', {}).get('flow', {}).get('ftp-data', 0)
        tftp_events = stats.get('app_layer', {}).get('flow', {}).get('tftp', 0)
        ikev2_data_events = stats.get('app_layer', {}).get('flow', {}).get('ikev2', 0)
        krb5_tcp_events = stats.get('app_layer', {}).get('flow', {}).get('krb5_tcp', 0)
        dhcp_events = stats.get('app_layer', {}).get('flow', {}).get('dhcp', 0)
        failed_tcp_events = stats.get('app_layer', {}).get('flow', {}).get('failed_tcp', 0)
        dcerpc_udp_events = stats.get('app_layer', {}).get('flow', {}).get('dcerpc_udp', 0)
        dns_udp_events = stats.get('app_layer', {}).get('flow', {}).get('dns_udp', 0)
        krb5_udp_events = stats.get('app_layer', {}).get('flow', {}).get('krb5_udp', 0)
        failed_udp_events = stats.get('app_layer', {}).get('flow', {}).get('failed_udp', 0)

        return cls(time, uptime, capture_kernel_packets, capture_kernel_drops, capture_errors,
                   flow_memory, tcp_memory, tcp_reassembly_memory, dns_memory, http_memory, ftp_memory, http_events,
                   tls_events, ssh_events, imap_events, msn_events, smb_events, dcerpc_tcp_events, dns_tcp_events,
                   nfs_tcp_events, ntp_events, ftp_data_events, tftp_events, ikev2_data_events, krb5_tcp_events,
                   dhcp_events, failed_tcp_events, dcerpc_udp_events, dns_udp_events, krb5_udp_events,
                   failed_udp_events)

    def __str__(self):
        return json.dumps(dict(
            timestamp=self.timestamp,
            time=str(self.time),
            uptime=self.uptime,
            capture_kernel_packets=self.capture_kernel_packets,
            capture_kernel_drops=self.capture_kernel_drops,
            capture_kernel_drops_percentage=self.capture_kernel_drops_percentage,
            capture_errors=self.capture_errors,
            flow_memory=self.flow_memory,
            tcp_memory=self.tcp_memory,
            tcp_reassembly_memory=self.tcp_reassembly_memory,
            dns_memory=self.dns_memory,
            http_memory=self.http_memory,
            ftp_memory=self.ftp_memory,
            total_memory=self.get_total_memory(),
            http_events=self.http_events,
            tls_events=self.tls_events,
            ssh_events=self.ssh_events,
            imap_events=self.imap_events,
            msn_events=self.msn_events,
            smb_events=self.smb_events,
            dcerpc_tcp_events=self.dcerpc_tcp_events,
            dns_tcp_events=self.dns_tcp_events,
            nfs_tcp_events=self.nfs_tcp_events,
            ntp_events=self.ntp_events,
            ftp_data_events=self.ftp_data_events,
            tftp_events=self.tftp_events,
            ikev2_data_events=self.ikev2_data_events,
            krb5_tcp_events=self.krb5_tcp_events,
            dhcp_events=self.dhcp_events,
            failed_tcp_events=self.failed_tcp_events,
            dcerpc_udp_events=self.dcerpc_udp_events,
            dns_udp_events=self.dns_udp_events,
            krb5_udp_events=self.krb5_udp_events,
            failed_udp_events=self.failed_udp_events
        ))

    def get_total_memory(self):
        """
        Get the total amount of memory being used (in bytes)

        > **Warning** Testing has proven this number to be unreliable.

        Returns:
            The total amount of memory being used by Suricata processes

        """
        return self.ftp_memory + self.http_memory + self.dns_memory + self.tcp_reassembly_memory + self.tcp_memory + \
               self.flow_memory

    def merge_metric_entry(self, metric_entry):
        """Merge another metrics entry into this one
        Args:
            metric_entry: The MetricsEntry you wish to merge in
        Returns:
            None
        """
        if not isinstance(metric_entry, MetricsEntry):
            return
        self.capture_kernel_packets += metric_entry.capture_kernel_packets
        self.capture_kernel_drops += metric_entry.capture_kernel_drops
        self.capture_errors += metric_entry.capture_errors
        self.ftp_memory = math.ceil((self.ftp_memory + metric_entry.ftp_memory) / 2)
        self.flow_memory = math.ceil((self.flow_memory + metric_entry.flow_memory) / 2)
        self.http_memory = math.ceil((self.http_memory + metric_entry.http_memory) / 2)
        self.dns_memory = math.ceil((self.dns_memory + metric_entry.dns_memory) / 2)
        self.tcp_memory = math.ceil((self.tcp_memory + metric_entry.tcp_memory) / 2)
        self.tcp_reassembly_memory = \
            math.ceil((self.tcp_reassembly_memory + metric_entry.tcp_reassembly_memory) / 2)
        self.http_events += metric_entry.http_events
        self.tls_events += metric_entry.tls_events
        self.ssh_events += metric_entry.ssh_events
        self.imap_events += metric_entry.imap_events
        self.msn_events += metric_entry.msn_events
        self.smb_events += metric_entry.smb_events
        self.dcerpc_tcp_events += metric_entry.dcerpc_tcp_events
        self.dns_tcp_events += metric_entry.dns_tcp_events
        self.nfs_tcp_events += metric_entry.nfs_tcp_events
        self.ntp_events += metric_entry.ntp_events
        self.ftp_data_events += metric_entry.ftp_data_events
        self.tftp_events += metric_entry.tftp_events
        self.ikev2_data_events += metric_entry.ikev2_data_events
        self.krb5_tcp_events += metric_entry.krb5_tcp_events
        self.dhcp_events += metric_entry.dhcp_events
        self.failed_tcp_events += metric_entry.failed_tcp_events
        self.dcerpc_udp_events += metric_entry.dcerpc_udp_events
        self.dns_udp_events += metric_entry.dns_udp_events
        self.krb5_udp_events += metric_entry.krb5_udp_events
        self.failed_udp_events += metric_entry.failed_udp_events
        if self.capture_kernel_packets > 0:
            self.capture_kernel_drops_percentage = round(self.capture_kernel_drops / self.capture_kernel_packets, 6)


class MainLog(logs.LogFile):
    """
    Provides an interface for working with suricata.log
    """

    def __init__(self, log_sample_size: Optional[int] = 10000):
        """Work with Suricata's suricata.log
        Args:
            log_sample_size: The maximum number of entries (or lines) to parse
        Returns:
            None
        """
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.suricata_logs = self.env_dict.get('SURICATA_LOGS')
        self.log_path = os.path.join(self.suricata_logs, 'suricata.log')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)

    def iter_entries(self, start: Optional[datetime] = None, end: Optional[datetime] = None,
                     log_level: Optional[str] = None, category: Optional[str] = None):
        """Iterate through MainEntries while providing some basic filtering options
        Args:
            start: UTC start time
            end: UTC end time
            log_level: DEBUG, INFO, WARN, ERROR, CRITICAL
            category: The log entry category
        Returns:
             yields a MainEntry for every iteration
        """

        def filter_entries(s=None, e=None):
            if not e:
                e = datetime.utcnow()
            if not s:
                s = datetime.utcnow() - timedelta(minutes=60)
            for en in self.entries:
                en = MainEntry(en)
                if s < en.time < e:
                    yield en

        for log_entry in filter_entries(start, end):
            if log_level:
                if log_entry.log_level.lower() != log_level.lower():
                    continue
            if category:
                if log_entry.category.lower() != category.lower():
                    continue
            yield log_entry

    def tail(self, pretty_print: Optional[bool] = True):
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
                                ['Time', 'Log Level', 'Category', 'Error', 'Error Code', 'Message'],
                                [entry.time, entry.log_level, entry.category, entry.error, entry.error_code,
                                 entry.message]
                            ]
                            print(tabulate.tabulate(status_table, tablefmt='fancy_grid'))
                    if len(visited) > 100:
                        visited = []
                start = datetime.utcnow() - timedelta(seconds=60)
                time.sleep(5)
        except KeyboardInterrupt:
            print(utilities.PrintDecorations.colorize('OK', 'green'))


class StatusLogEve(logs.LogFile):

    """A status entry from Suricata's eve.json"""

    def __init__(self, log_sample_size: Optional[int] = 10000):
        """A status entry from eve.json log
        Args:
            log_sample_size: The maximum number of entries (or lines) to parse
        """
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.suricata_logs = self.env_dict.get('SURICATA_LOGS')
        self.log_path = os.path.join(self.suricata_logs, 'eve.json')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)

    def iter_metrics(self, start=None, end=None):
        """Iterate through metrics entries individually.

        Args:
            start: UTC start time
            end: UTC end time
        Returns:
             yields a MetricsEntry for every iteration
        """
        def filter_metrics(s=None, e=None):
            if not e:
                e = datetime.utcnow()
            if not s:
                s = datetime.utcnow() - timedelta(minutes=60)
            prev_en = None
            for en_raw in self.entries:
                if '"event_type":"stats"' in en_raw:
                    try:
                        en = MetricsEntry.create_from_eve_raw_stats(json.loads(en_raw))
                    except ValueError:
                        continue
                    en_corrected = MetricsEntry.create_from_eve_raw_stats(json.loads(en_raw))
                    if s < en.time < e:
                        if not prev_en:
                            prev_en = en
                            continue

                        # A lot of Suricata stats are counters, meaning that they increment from zero starting at
                        # process start. We address this by applying the difference between the current and previous
                        # entries so that each entry represents an increment
                        en_corrected.capture_kernel_packets = \
                            max(0, en.capture_kernel_packets - prev_en.capture_kernel_packets)
                        en_corrected.capture_errors = max(0, en.capture_errors - prev_en.capture_errors)
                        en_corrected.capture_kernel_drops = \
                            max(0, en.capture_kernel_drops - prev_en.capture_kernel_drops)

                        en_corrected.http_events = max(0, en.http_events - prev_en.http_events)
                        en_corrected.tls_events = max(0, en.tls_events - prev_en.tls_events)
                        en_corrected.ssh_events = max(0, en.ssh_events - prev_en.ssh_events)
                        en_corrected.imap_events = max(0, en.imap_events - prev_en.imap_events)
                        en_corrected.msn_events = max(0, en.msn_events - prev_en.msn_events)
                        en_corrected.smb_events = max(0, en.smb_events - prev_en.smb_events)
                        en_corrected.dcerpc_tcp_events = max(0, en.dcerpc_tcp_events - prev_en.dcerpc_tcp_events)
                        en_corrected.dns_tcp_events = max(0, en.dns_tcp_events - prev_en.dns_tcp_events)
                        en_corrected.nfs_tcp_events = max(0, en.nfs_tcp_events - prev_en.nfs_tcp_events)
                        en_corrected.ntp_events = max(0, en.ntp_events - prev_en.ntp_events)
                        en_corrected.ftp_data_events = max(0, en.ftp_data_events - prev_en.ftp_data_events)
                        en_corrected.tftp_events = max(0, en.tftp_events - prev_en.tftp_events)
                        en_corrected.ikev2_data_events = max(0, en.ikev2_data_events - prev_en.ikev2_data_events)
                        en_corrected.krb5_tcp_events = max(0, en.krb5_tcp_events - prev_en.krb5_tcp_events)
                        en_corrected.dhcp_events = max(0, en.dhcp_events - prev_en.dhcp_events)
                        en_corrected.failed_tcp_events = max(0, en.failed_tcp_events - prev_en.failed_tcp_events)
                        en_corrected.dcerpc_udp_events = max(0, en.dcerpc_udp_events - prev_en.dcerpc_udp_events)
                        en_corrected.dns_udp_events = max(0, en.dns_udp_events - prev_en.dns_udp_events)
                        en_corrected.krb5_udp_events = max(0, en.krb5_udp_events - prev_en.krb5_udp_events)
                        en_corrected.failed_udp_events = max(0, en.failed_udp_events - prev_en.failed_udp_events)

                        prev_en = en
                        yield en_corrected

        for log_entry in filter_metrics(start, end):
            yield log_entry

    def iter_aggregated_metrics(self, start=None, end=None, tolerance_seconds=60):
        """Aggregate events within tolerance_seconds into the same entry.

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
        sorted_by_time = sorted(sorted_by_time, key=lambda x: x.time)
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


class StatsLog(logs.LogFile):
    """
    Provides an interface for working with Suricata's stats.log
    """
    def __init__(self, log_sample_size: Optional[int] = 10000):
        """Work with Suricata's stats.log
        Args:
            log_sample_size: The maximum number of entries (or lines) to parse.
        ---

        > The size of `log_sample_size` is set significantly higher as log entries can span multiple lines.
        """
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.suricata_logs = self.env_dict.get('SURICATA_LOGS')
        self.log_path = os.path.join(self.suricata_logs, 'stats.log')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)
        self.log_path = os.path.join(self.suricata_logs, 'stats.log')

    def _state_machine_parser(self):
        temp_entries = []
        date_token = 'Date:'
        section_token = '------------------------------------------------------------------------------------'
        timezone_utc_offset_seconds = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        timezone_utc_offset_seconds *= -1
        utc_datetime = None
        entered_counter_area = False
        stats_entry = {}
        for line in self.entries:
            line = str(line)
            if section_token in line:
                continue
            elif date_token in line:
                try:
                    _, mm_dd_yyyy, _, hh_mm_ss, _, _, _, _, _ = line.split(' ')
                except ValueError:
                    continue
                local_datetime = datetime.strptime(f'{mm_dd_yyyy} {hh_mm_ss}', '%m/%d/%Y %H:%M:%S')
                utc_datetime = local_datetime - timedelta(seconds=timezone_utc_offset_seconds)
                entered_counter_area = True
            elif entered_counter_area:
                metric, _, counter = line.replace(' ', '').strip().split('|')
                if stats_entry:
                    stats_entry.update({metric: int(counter)})
                else:
                    stats_entry = {'time': utc_datetime}
                if metric == 'flow.memuse':
                    temp_entries.append(stats_entry)
                    stats_entry = {}
                    entered_counter_area = False
        self.entries = temp_entries

    def iter_metrics(self, start: Optional[datetime] = None, end: Optional[datetime] = None):
        """Iterate through metrics entries individually.

        Args:
            start: UTC start time
            end: UTC end time
        Returns:
             yields a MetricsEntry for every iteration
        """
        self._state_machine_parser()

        def filter_metrics(s=None, e=None):
            if not e:
                e = datetime.utcnow()
            if not s:
                s = datetime.utcnow() - timedelta(minutes=60)
            prev_en = None
            for en_dict in self.entries:
                try:
                    en = MetricsEntry.create_from_raw_stats_entry(en_dict)
                except ValueError:
                    continue
                en_corrected = MetricsEntry.create_from_raw_stats_entry(en_dict)
                if s < en.time < e:
                    if not prev_en:
                        prev_en = en
                        continue

                    # A lot of Suricata stats are counters, meaning that they increment from zero starting at
                    # process start. We address this by applying the difference between the current and previous
                    # entries so that each entry represents an increment
                    en_corrected.capture_kernel_packets = \
                        max(0, en.capture_kernel_packets - prev_en.capture_kernel_packets)
                    en_corrected.capture_errors = max(0, en.capture_errors - prev_en.capture_errors)
                    en_corrected.capture_kernel_drops = \
                        max(0, en.capture_kernel_drops - prev_en.capture_kernel_drops)

                    en_corrected.http_events = max(0, en.http_events - prev_en.http_events)
                    en_corrected.tls_events = max(0, en.tls_events - prev_en.tls_events)
                    en_corrected.ssh_events = max(0, en.ssh_events - prev_en.ssh_events)
                    en_corrected.imap_events = max(0, en.imap_events - prev_en.imap_events)
                    en_corrected.msn_events = max(0, en.msn_events - prev_en.msn_events)
                    en_corrected.smb_events = max(0, en.smb_events - prev_en.smb_events)
                    en_corrected.dcerpc_tcp_events = max(0, en.dcerpc_tcp_events - prev_en.dcerpc_tcp_events)
                    en_corrected.dns_tcp_events = max(0, en.dns_tcp_events - prev_en.dns_tcp_events)
                    en_corrected.nfs_tcp_events = max(0, en.nfs_tcp_events - prev_en.nfs_tcp_events)
                    en_corrected.ntp_events = max(0, en.ntp_events - prev_en.ntp_events)
                    en_corrected.ftp_data_events = max(0, en.ftp_data_events - prev_en.ftp_data_events)
                    en_corrected.tftp_events = max(0, en.tftp_events - prev_en.tftp_events)
                    en_corrected.ikev2_data_events = max(0, en.ikev2_data_events - prev_en.ikev2_data_events)
                    en_corrected.krb5_tcp_events = max(0, en.krb5_tcp_events - prev_en.krb5_tcp_events)
                    en_corrected.dhcp_events = max(0, en.dhcp_events - prev_en.dhcp_events)
                    en_corrected.failed_tcp_events = max(0, en.failed_tcp_events - prev_en.failed_tcp_events)
                    en_corrected.dcerpc_udp_events = max(0, en.dcerpc_udp_events - prev_en.dcerpc_udp_events)
                    en_corrected.dns_udp_events = max(0, en.dns_udp_events - prev_en.dns_udp_events)
                    en_corrected.krb5_udp_events = max(0, en.krb5_udp_events - prev_en.krb5_udp_events)
                    en_corrected.failed_udp_events = max(0, en.failed_udp_events - prev_en.failed_udp_events)

                    prev_en = en
                    yield en_corrected

        for log_entry in filter_metrics(start, end):
            yield log_entry

    def iter_aggregated_metrics(self, start: Optional[datetime] = None, end: Optional[datetime] = None,
                                tolerance_seconds: Optional[int] = 60):
        """Aggregate events within tolerance_seconds into the same entry.

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
        sorted_by_time = sorted(sorted_by_time, key=lambda x: x.time)
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

    def tail(self, pretty_print: Optional[bool] = True):
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
                                ['Time', 'Memory', 'Packets Captured', 'Packets Dropped',
                                 'Errors During Capture'],
                                [metric.time, metric.get_total_memory(), metric.capture_kernel_packets,
                                 metric.capture_kernel_drops, metric.capture_errors]
                            ]
                            print(tabulate.tabulate(status_table, tablefmt='fancy_grid'))
                    if len(visited) > 100:
                        visited = []
                start = datetime.utcnow() - timedelta(seconds=60)
                time.sleep(5)
        except KeyboardInterrupt:
            print(utilities.PrintDecorations.colorize('OK', 'green'))
