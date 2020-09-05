import os
import json
from datetime import datetime
from datetime import timedelta
from dynamite_nsm import const
from dynamite_nsm.services.base import logs


def parse_suricata_datetime(t):

    ret = datetime.strptime(t[0:22], '%Y-%m-%dT%H:%M:%S.%f')
    if t[26] == '+':
        ret -= timedelta(hours=int(t[27:29]), minutes=int(t[30:]))
    elif t[26] == '-':
        ret += timedelta(hours=int(t[27:29]), minutes=int(t[30:]))
    return ret


class MetricsEntry:

    def __init__(self, entry_raw):
        self.entry_raw = entry_raw
        self.stats = entry_raw['stats']
        self.timestamp = self.entry_raw.get('timestamp')
        self.time = parse_suricata_datetime(self.timestamp)
        self.uptime = self.stats.get('uptime')
        self.capture_kernel_packets = self.stats.get('capture', {}).get('kernel_packets')
        self.capture_kernel_drops = self.stats.get('capture', {}).get('kernel_drops')
        self.capture_errors = self.stats.get('capture', {}).get('errors')
        self.flow_memory = self.stats.get('flow', {}).get('memuse')
        self.tcp_memory = self.stats.get('tcp', {}).get('memuse')
        self.tcp_reassembly_memory = self.stats.get('tcp', {}).get('reassembly_memuse')
        self.dns_memory = self.stats.get('dns', {}).get('memuse')
        self.http_memory = self.stats.get('http', {}).get('memuse')
        self.ftp_memory = self.stats.get('ftp', {}).get('memuse')

    def get_total_memory(self):
        return self.ftp_memory + self.http_memory + self.dns_memory + self.tcp_reassembly_memory + self.tcp_memory + \
               self.flow_memory

    def __str__(self):
        return json.dumps(dict(
            timestamp=self.timestamp,
            time=str(self.time),
            uptime=self.uptime,
            capture_kernel_packets=self.capture_kernel_packets,
            capture_kernel_drops=self.capture_kernel_drops,
            capture_errors=self.capture_errors,
            flow_memory=self.flow_memory,
            tcp_memory=self.tcp_memory,
            tcp_reassembly_memory=self.tcp_reassembly_memory,
            dns_memory=self.dns_memory,
            http_memory=self.http_memory,
            ftp_memory=self.ftp_memory,
            total_memory=self.get_total_memory()
        ))


class StatusLog(logs.LogFile):

    def __init__(self, log_sample_size=500):
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
            for en in self.entries:
                if '"event_type":"stats"' in en:
                    en = MetricsEntry(json.loads(en))
                    if s or e:
                        if s < en.time < e:
                            yield en
                    else:
                        yield en
        for log_entry in filter_metrics(start, end):
            yield log_entry
