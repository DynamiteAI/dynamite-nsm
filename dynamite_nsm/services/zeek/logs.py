import os
import json
import itertools
from datetime import datetime
from datetime import timedelta
from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base import logs


def parse_zeek_datetime(t):
    return datetime.utcfromtimestamp(int(str(t).split('.')[0]))


class MetricsEntry:

    def __init__(self, entry_raw):
        self.entry_raw = entry_raw
        self.timestamp = entry_raw.get('ts')
        self.time = parse_zeek_datetime(self.timestamp)
        self.peer = entry_raw.get('peer')
        self.peers = [self.peer]
        self.memory = entry_raw.get('mem', 0)
        self.packets_processed = entry_raw.get('pkts_proc', 0)
        self.bytes_received = entry_raw.get('bytes_recv', 0)
        self.packets_dropped = entry_raw.get('pkts_dropped', 0)
        self.packets_link = entry_raw.get('pkts_link', 0)
        self.packet_lag = entry_raw.get('pkt_lag', 0)
        self.events_processed = entry_raw.get('events_proc', 0)
        self.events_queued = entry_raw.get('events_queued', 0)
        self.active_tcp_connections = entry_raw.get('active_tcp_conns', 0)
        self.active_udp_connections = entry_raw.get('active_udp_conns', 0)
        self.active_icmp_connections = entry_raw.get('active_icmp_conns', 0)
        self.tcp_connections = entry_raw.get('tcp_conns', 0)
        self.udp_connections = entry_raw.get('udp_conns', 0)
        self.icmp_connections = entry_raw.get('icmp_conns', 0)
        self.timers = entry_raw.get('timers', 0)
        self.files = entry_raw.get('files', 0)
        self.active_files = entry_raw.get('active_files', 0)
        self.dns_requests = entry_raw.get('dns_requests', 0)
        self.active_dns_requests = entry_raw.get('active_dns_requests', 0)
        self.reassembly_tcp_size = entry_raw.get('reassem_tcp_size', 0)
        self.reassembly_file_size = entry_raw.get('reassem_file_size', 0)
        self.reassembly_fragment_size = entry_raw.get('reassem_frag_size', 0)
        self.reassembly_unknown_size = entry_raw.get('reassem_unknown_size', 0)
        self.packets_dropped_percentage = 0
        if self.packets_processed > 0:
            self.packets_dropped_percentage = round(self.packets_dropped / self.packets_processed, 2)

    def merge_metric_entry(self, metric_entry):
        if not isinstance(metric_entry, MetricsEntry):
            return
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
            self.packets_dropped_percentage = round(self.packets_dropped/self.packets_processed, 6)

    def __str__(self):
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


class StatusLog(logs.LogFile):

    def __init__(self, log_sample_size=500):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.zeek_home = self.env_dict.get('ZEEK_HOME')
        self.log_path = os.path.join(self.zeek_home, 'logs', 'current', 'stats.log')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)

    def iter_metrics(self, start=None, end=None):
        def filter_metrics(s=None, e=None):
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

    def iter_aggregated_metrics(self, start=None, end=None, tolerance_seconds=60):
        """
        Zeek's stats.log returns a metric entry for every peer. This aggregation method will group events
        by the tolerance_seconds parameter

        In practice metrics aggregated like this will provide an accurate summation of Zeek resources at each point

        :param start: UTC start time
        :param end: UTC end time
        :param tolerance_seconds: Specifies the maximum numbers seconds between entries to consider them common,
                                  and therefore aggregate.
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
