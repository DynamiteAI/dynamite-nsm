import itertools
import json
import math
import os
import time
from datetime import datetime
from datetime import timedelta

from dynamite_nsm import const
from dynamite_nsm import utilities
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

    def __init__(self, time, uptime, capture_kernel_packets, capture_kernel_drops, capture_errors,
                 flow_memory, tcp_memory, tcp_reassembly_memory, dns_memory, http_memory, ftp_memory, http_events,
                 tls_events, ssh_events, imap_events, msn_events, smb_events, dcerpc_tcp_events, dns_tcp_events,
                 nfs_tcp_events, ntp_events, ftp_data_events, tftp_events, ikev2_data_events, krb5_tcp_events,
                 dhcp_events, failed_tcp_events, dcerpc_udp_events, dns_udp_events, krb5_udp_events, failed_udp_events):

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
    def create_from_raw_stats_entry(cls, entry_raw_stats):
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
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.suricata_logs = self.env_dict.get('SURICATA_LOGS')
        self.log_path = os.path.join(self.suricata_logs, 'suricata.log')

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


class StatusLogEve(logs.LogFile):

    def __init__(self, log_sample_size=10000):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.suricata_logs = self.env_dict.get('SURICATA_LOGS')
        self.log_path = os.path.join(self.suricata_logs, 'eve.json')

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


class StatsLog(StatusLogEve):

    def __init__(self, log_sample_size=10000):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.suricata_logs = self.env_dict.get('SURICATA_LOGS')

        StatusLogEve.__init__(self, log_sample_size=log_sample_size)
        self.log_path = os.path.join(self.suricata_logs, 'stats.log')
        self._state_machine_parser()

    def _state_machine_parser(self):
        self.entries = []
        date_token = 'Date:'
        section_token = '------------------------------------------------------------------------------------'
        timezone_utc_offset_seconds = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        timezone_utc_offset_seconds *= -1
        utc_datetime = None
        entered_counter_area = False
        stats_entry = {}
        for line in self.iter_cache():
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
                    self.entries.append(stats_entry)
                    stats_entry = {}
                    entered_counter_area = False

    def iter_metrics(self, start=None, end=None):
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
