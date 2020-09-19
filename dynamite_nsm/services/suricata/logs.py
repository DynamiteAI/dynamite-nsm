import os
import math
import json
import itertools

from datetime import datetime
from datetime import timedelta
from dynamite_nsm import const
from dynamite_nsm.services.base import logs
from dynamite_nsm.services.suricata import exceptions as suricata_exceptions


def parse_suricata_datetime(t):
    ret = datetime.strptime(t[0:22], '%Y-%m-%dT%H:%M:%S.%f')
    if t[26] == '+':
        ret -= timedelta(hours=int(t[27:29]), minutes=int(t[30:]))
    elif t[26] == '-':
        ret += timedelta(hours=int(t[27:29]), minutes=int(t[30:]))
    return ret


class MainEntry:

    LOG_LEVEL_MAP = dict(
        Debug="DEBUG",
        Info="INFO",
        Notice="NOTICE",
        Warning="WARN",
        Error="ERROR",
        Critical="CRITICAL"
    )

    def __init__(self, entry_raw):
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
            raise suricata_exceptions.InvalidSuricataStatusLogEntry(
                'suricata.log entry is not JSON formatted. '
                'Make sure to enable logging.file.type="json" in suricata.yaml.')
        self.timestamp = entry.get('timestamp')
        self.log_level = entry.get('log_level')
        self.category = entry.get('event_type')
        self.error_code = entry.get('engine', {}).get('error_code', 0)
        self.error = entry.get('engine', {}).get('error', None)
        self.message = entry.get('engine', {}).get('message', None)
        if not self.timestamp:
            raise suricata_exceptions.InvalidSuricataStatusLogEntry('Missing timestamp field')
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

    def __init__(self, entry_raw):
        self.entry_raw = entry_raw
        self.stats = entry_raw['stats']
        self.timestamp = self.entry_raw.get('timestamp')
        self.time = parse_suricata_datetime(self.timestamp)
        self.uptime = self.stats.get('uptime')
        self.capture_kernel_packets = self.stats.get('capture', {}).get('kernel_packets', 0)
        self.capture_kernel_drops = self.stats.get('capture', {}).get('kernel_drops', 0)
        self.capture_errors = self.stats.get('capture', {}).get('errors', 0)
        self.flow_memory = self.stats.get('flow', {}).get('memuse', 0)
        self.tcp_memory = self.stats.get('tcp', {}).get('memuse', 0)
        self.tcp_reassembly_memory = self.stats.get('tcp', {}).get('reassembly_memuse', 0)
        self.dns_memory = self.stats.get('dns', {}).get('memuse', 0)
        self.http_memory = self.stats.get('http', {}).get('memuse', 0)
        self.ftp_memory = self.stats.get('ftp', {}).get('memuse', 0)
        self.http_events = self.stats.get('app_layer', {}).get('flow', {}).get('http', 0)
        self.tls_events = self.stats.get('app_layer', {}).get('flow', {}).get('tls', 0)
        self.ssh_events = self.stats.get('app_layer', {}).get('flow', {}).get('ssh', 0)
        self.imap_events = self.stats.get('app_layer', {}).get('flow', {}).get('imap', 0)
        self.msn_events = self.stats.get('app_layer', {}).get('flow', {}).get('msn', 0)
        self.smb_events = self.stats.get('app_layer', {}).get('flow', {}).get('smb', 0)
        self.dcerpc_tcp_events = self.stats.get('app_layer', {}).get('flow', {}).get('dcerpc_tcp', 0)
        self.dns_tcp_events = self.stats.get('app_layer', {}).get('flow', {}).get('dns_tcp', 0)
        self.nfs_tcp_events = self.stats.get('app_layer', {}).get('flow', {}).get('nfs_tcp', 0)
        self.ntp_events = self.stats.get('app_layer', {}).get('flow', {}).get('ntp', 0)
        self.ftp_data_events = self.stats.get('app_layer', {}).get('flow', {}).get('ftp-data', 0)
        self.tftp_events = self.stats.get('app_layer', {}).get('flow', {}).get('tftp', 0)
        self.ikev2_data_events = self.stats.get('app_layer', {}).get('flow', {}).get('ikev2', 0)
        self.krb5_tcp_events = self.stats.get('app_layer', {}).get('flow', {}).get('krb5_tcp', 0)
        self.dhcp_events = self.stats.get('app_layer', {}).get('flow', {}).get('dhcp', 0)
        self.failed_tcp_events = self.stats.get('app_layer', {}).get('flow', {}).get('failed_tcp', 0)
        self.dcerpc_udp_events = self.stats.get('app_layer', {}).get('flow', {}).get('dcerpc_udp', 0)
        self.dns_udp_events = self.stats.get('app_layer', {}).get('flow', {}).get('dns_udp', 0)
        self.krb5_udp_events = self.stats.get('app_layer', {}).get('flow', {}).get('krb5_udp', 0)
        self.failed_udp_events = self.stats.get('app_layer', {}).get('flow', {}).get('failed_udp', 0)
        self.capture_kernel_drops_percentage = 0
        if self.capture_kernel_packets > 0:
            self.capture_kernel_drops_percentage = round(self.capture_kernel_drops / self.capture_kernel_packets, 2)

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
        return self.ftp_memory + self.http_memory + self.dns_memory + self.tcp_reassembly_memory + self.tcp_memory + \
               self.flow_memory

    def merge_metric_entry(self, metric_entry):
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

    def __init__(self, log_sample_size=10000):
        self.log_path = os.path.join(const.LOG_PATH, 'suricata', 'suricata.log')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)

    def iter_entries(self, start=None, end=None, log_level=None, category=None):

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


class StatusLog(logs.LogFile):

    def __init__(self, log_sample_size=10000):
        self.log_path = os.path.join(const.LOG_PATH, 'suricata', 'eve.json')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)

    def iter_metrics(self, start=None, end=None):
        def filter_metrics(s=None, e=None):
            if not e:
                e = datetime.utcnow()
            if not s:
                s = datetime.utcnow() - timedelta(minutes=60)
            prev_en = None
            for en_raw in self.entries:
                if '"event_type":"stats"' in en_raw:
                    en = MetricsEntry(json.loads(en_raw))
                    en_corrected = MetricsEntry(json.loads(en_raw))
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
        """
        :param start: UTC start time
        :param end: UTC end time
        :param tolerance_seconds: Specifies the maximum numbers seconds between entries to consider them common,
                                  and therefore aggregate.
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
