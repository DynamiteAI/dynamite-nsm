import os
import json
from datetime import datetime
from datetime import timedelta
from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.filebeat import exceptions as filebeat_exceptions


def parse_filebeat_datetime(t):

    ret = datetime.strptime(t[0:22], '%Y-%m-%dT%H:%M:%S.%f')
    if t[23] == '+':
        ret -= timedelta(hours=int(t[24:26]), minutes=int(t[27:]))
    elif t[23] == '-':
        ret += timedelta(hours=int(t[24:26]), minutes=int(t[27:]))
    return ret


class MetricsEntry:

    def __init__(self, monitoring_payload, time):
        self.monitoring_payload = monitoring_payload
        try:
            metrics = self.monitoring_payload["monitoring"]["metrics"]
        except KeyError:
            raise Exception
        self.time = time
        self.open_handles = metrics.get("beat", {}).get("handles", {}).get("open", 0)
        self.memory_allocated = metrics.get("beat", {}).get("memstats", {}).get("memory_alloc", 0)
        self.harvester_open_files = metrics.get("filebeat", {}).get("harvester", {}).get("open_files", 0)
        self.harvester_running_files = metrics.get("filebeat", {}).get("harvester", {}).get("running_files", 0)
        self.write_bytes = metrics.get("libbeat", {}).get("output", {}).get("write", {}).get("bytes", 0)
        self.read_bytes = metrics.get("libbeat", {}).get("output", {}).get("read", {}).get("bytes", 0)
        self.active_events = metrics.get("libbeat", {}).get("pipeline", {}).get("events", {}).get("active", 0)
        self.published_events = metrics.get("libbeat", {}).get("pipeline", {}).get("events", {}).get("published", 0)

    def __str__(self):
        return json.dumps(dict(
            time=str(self.time),
            open_handles=self.open_handles,
            memory_allocated=self.memory_allocated,
            harvester_open_files=self.harvester_open_files,
            harvester_running_files=self.harvester_running_files,
            read_bytes=self.read_bytes,
            write_bytes=self.write_bytes,
            active_events=self.active_events,
            published_events=self.published_events
        ))


class StatusEntry:

    def __init__(self, entry_raw):
        self.entry_raw = entry_raw
        self.json_payload = False
        self.payload = None
        self.metrics = None
        self.message = None
        self.description = None
        self.category = None
        self.timestamp = None
        self.log_level = None
        self._parse_entry()

    def _parse_entry(self):
        log_entry = self.entry_raw.replace("\n", "").split('\t')
        if len(log_entry) == 4:
            self.timestamp, self.log_level, _, self.message = log_entry
            self.category = "harvester"
        elif len(log_entry) == 5:
            self.timestamp, self.log_level, self.category, _, self.message = log_entry
            self.category = self.category[1:-1]
        elif len(log_entry) == 6:
            self.timestamp, self.log_level, self.category, _, self.message, self.payload = log_entry
            self.category = self.category[1:-1]
        else:
            raise filebeat_exceptions.InvalidFilebeatStatusLogEntry("Unrecognized entity length {}".format(len(log_entry)))
        self.time = parse_filebeat_datetime(self.timestamp)
        if self.payload and ("[" in self.payload or "{" in self.payload):
            try:
                self.payload = json.loads(self.payload)
                self.json_payload = True
                if self.payload.get("monitoring"):
                    self.metrics = MetricsEntry(self.payload, self.time)
            except ValueError:
                pass

    def __str__(self):
        return json.dumps(
            dict(
                time=str(self.time),
                log_level=self.log_level,
                category=self.category,
                message=self.message,
                json_payload=self.json_payload
            )
        )


class StatusLog:

    def __init__(self, log_sample_size=500, process_entire_log=False):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.filebeat_home = self.env_dict.get('FILEBEAT_HOME')
        self.log_path = os.path.join(self.filebeat_home, 'logs', 'filebeat')

        self.exists = False
        self.entries = []
        self.latest_offset = 0
        self.refresh_latest_offset()
        if process_entire_log:
            self.build_recent_entries(1000000)
        else:
            self.build_recent_entries(log_sample_size)

    def __len__(self):
        return self.latest_offset

    def refresh_latest_offset(self):
        """
        Sets the latest line number offset in the current file.
        """
        try:
            with open(self.log_path) as f:
                for i, l in enumerate(f):
                    pass
                self.latest_offset = i + 1
                self.exists = True
        except IOError:
            self.latest_offset = 0

    def build_recent_entries(self, n):
        if not self.exists:
            raise FileNotFoundError(self.log_path)
        if n > self.latest_offset:
            start_line_offset = 0
        else:
            start_line_offset = self.latest_offset - n
        entries = []
        with open(self.log_path) as f:
            current_offset = 0
            while True:
                entry = f.readline()
                if not entry:
                    break
                if current_offset > start_line_offset:
                    entry = StatusEntry(entry)
                    entries.append(entry)
                current_offset += 1
        self.entries = entries

    def iter_entries(self, start=None, end=None, log_level=None, category=None):

        def filter_entries(s=None, e=None):
            if s and not e:
                e = datetime.utcnow()
            elif e and not s:
                s = datetime.utcnow() - timedelta(minutes=60)
            for en in self.entries:
                if s or e:
                    if s < en.time < e:
                        yield en
                else:
                    yield entry
        for log_entry in filter_entries(start, end):

            if log_level:
                if log_entry.log_level.lower() != log_level.lower():
                    continue
            if category:
                if log_entry.category.lower() != category.lower():
                    continue
            yield log_entry

    def iter_metrics(self, start=None, end=None):
        for entry in self.iter_entries(start, end):
            if entry.metrics:
                yield entry.metrics


log = StatusLog()
for entry in log.iter_entries(start=datetime.utcnow() - timedelta(minutes=60, days=1), log_level='INFO'):
    print(entry)
