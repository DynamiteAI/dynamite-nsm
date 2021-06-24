from __future__ import annotations

import itertools
import json
import math
import time
import os
from datetime import datetime
from datetime import timedelta
from typing import Dict, Optional

import tabulate

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base import logs


def parse_filebeat_datetime(t: str) -> datetime:
    """Parse a common filebeat timestamp string
    Args:
        t: A '%Y-%m-%dT%H:%M:%S.%f' formatted string

    Returns:
        A datetime object
    """
    ret = datetime.strptime(t[0:22], '%Y-%m-%dT%H:%M:%S.%f')
    if t[23] == '+':
        ret -= timedelta(hours=int(t[24:26]), minutes=int(t[27:]))
    elif t[23] == '-':
        ret += timedelta(hours=int(t[24:26]), minutes=int(t[27:]))
    return ret


class InvalidFilebeatStatusLogEntry(Exception):

    def __init__(self, message):
        """Thrown when a Filebeat log entry is improperly formatted
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "FileBeat log entry is invalid: {}".format(message)
        super(InvalidFilebeatStatusLogEntry, self).__init__(msg)


class MetricsEntry:
    """
    A single Filebeat metrics entry for a specific time-interval
    """

    def __init__(self, monitoring_payload: Dict, time: datetime):
        """Initialize metrics entry object
        Args:
            monitoring_payload: The serialized JSON for "monitoring" status types
            time: A datetime object representing when the metrics entry was written
        """

        self.monitoring_payload = monitoring_payload
        metrics = self.monitoring_payload["monitoring"]["metrics"]
        self.time = time
        self.open_file_handles = metrics.get("beat", {}).get("handles", {}).get("open", 0)
        self.memory_allocated = metrics.get("beat", {}).get("memstats", {}).get("memory_alloc", 0)
        self.harvester_open_files = metrics.get("filebeat", {}).get("harvester", {}).get("open_files", 0)
        self.harvester_running_files = metrics.get("filebeat", {}).get("harvester", {}).get("running_files", 0)
        self.write_bytes = metrics.get("libbeat", {}).get("output", {}).get("write", {}).get("bytes", 0)
        self.read_bytes = metrics.get("libbeat", {}).get("output", {}).get("read", {}).get("bytes", 0)
        self.active_events = metrics.get("libbeat", {}).get("pipeline", {}).get("events", {}).get("active", 0)
        self.published_events = metrics.get("libbeat", {}).get("pipeline", {}).get("events", {}).get("published", 0)

    def merge_metric_entry(self, metric_entry: MetricsEntry) -> None:
        """Merge another metrics entry into this one
        Args:
            metric_entry: The MetricsEntry you wish to merge in
        Returns:
            None
        """
        self.open_file_handles = math.ceil((self.open_file_handles + metric_entry.open_file_handles) / 2)
        self.memory_allocated = math.ceil((self.memory_allocated + metric_entry.memory_allocated) / 2)
        self.harvester_open_files = math.ceil((self.harvester_open_files + metric_entry.harvester_open_files) / 2)
        self.harvester_running_files = math.ceil(
            (self.harvester_running_files + metric_entry.harvester_running_files) / 2)
        self.write_bytes += metric_entry.write_bytes
        self.read_bytes += metric_entry.read_bytes
        self.active_events += metric_entry.active_events
        self.published_events += metric_entry.published_events

    def __str__(self) -> str:
        return json.dumps(dict(
            time=str(self.time),
            open_file_handles=self.open_file_handles,
            memory_allocated=self.memory_allocated,
            harvester_open_files=self.harvester_open_files,
            harvester_running_files=self.harvester_running_files,
            read_bytes=self.read_bytes,
            write_bytes=self.write_bytes,
            active_events=self.active_events,
            published_events=self.published_events
        ))


class StatusEntry:
    """
    An entry from Filebeat's main log; automatically parses out MetricsEntries into their own dedicated object
    """

    def __init__(self, entry_raw: str, include_json_payload: Optional[bool] = False):
        """A status entry
        Args:
            entry_raw: A line item representing a single entry within the Filebeat log
            include_json_payload: If, True, then the metrics payload will be included in its raw JSON form
        """

        self.include_json_payload = include_json_payload
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

    def _parse_entry(self) -> None:
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
            raise InvalidFilebeatStatusLogEntry(
                "Unrecognized entity length {}".format(len(log_entry)))
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
        log_entry = dict(
            time=str(self.time),
            log_level=self.log_level,
            category=self.category,
            message=self.message,
            json_payload=self.json_payload,
        )
        if self.include_json_payload:
            log_entry['json_payload_raw'] = self.payload
        return json.dumps(log_entry)


class StatusLog(logs.LogFile):
    """
    Provides an interface for working with Filebeat's main log
    """

    def __init__(self, log_sample_size: Optional[int] = 500, include_json_payloads: Optional[bool] = False):
        """Work with Filebeat's filebeat.log
        Args:
            log_sample_size: The maximum number of entries to parse
            include_json_payloads: If, True, then metrics payloads will be included in their raw JSON form
        """

        self.include_json_payloads = include_json_payloads
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.filebeat_home = self.env_dict.get('FILEBEAT_HOME')
        self.log_path = os.path.join(self.filebeat_home, 'logs', 'filebeat')

        logs.LogFile.__init__(self,
                              log_path=self.log_path,
                              log_sample_size=log_sample_size)

    def iter_entries(self, start: Optional[datetime] = None, end: Optional[datetime] = None, log_level=None,
                     category=None):
        """Iterate through StatusEntries while providing some basic filtering options
        Args:
            start: UTC start time
            end: UTC end time
            log_level: DEBUG, INFO, WARN, ERROR, CRITICAL
            category: Defaults to all if none specified; valid categories are beat, cfgwarn, crawler, harvester, monitoring, publisher, registrar, seccomp
        Returns:
             yields a StatusEntry for every iteration
        """

        def filter_entries(s: Optional[datetime], e: Optional[datetime] = None):
            if not e:
                e = datetime.utcnow()
            if not s:
                s = datetime.utcnow() - timedelta(minutes=60)
            for en in self.entries:
                try:
                    en = StatusEntry(en, include_json_payload=self.include_json_payloads)
                except InvalidFilebeatStatusLogEntry:
                    continue
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

    def iter_metrics(self, start: Optional[datetime] = None, end: Optional[datetime] = None):
        """Iterate through metrics entries individually
        Args:
            start: UTC start time
            end: UTC end time
        Returns:
             yields a MetricsEntry for every iteration
        """
        for entry in self.iter_entries(start, end):
            if entry.metrics:
                yield entry.metrics

    def iter_aggregated_metrics(self, start: Optional[datetime] = None, end: Optional[datetime] = None,
                                tolerance_seconds: Optional[int] = 60):
        """Iterates through metric entries, while aggregating entries together that are within the same tolerance_seconds into a single MetricsEntry
        Args:
            start: UTC start time
            end: UTC end time
            tolerance_seconds: Specifies the maximum numbers seconds between entries to consider them common, and therefore aggregate.
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

    def tail_entries(self, pretty_print: Optional[bool] = True):
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
                                ['Time', 'Log Level', 'Category', 'Message'],
                                [entry.time, entry.log_level, entry.category, entry.message]
                            ]
                            print(tabulate.tabulate(status_table, tablefmt='fancy_grid'))
                    if len(visited) > 100:
                        visited = []
                start = datetime.utcnow() - timedelta(seconds=60)
                time.sleep(5)
        except KeyboardInterrupt:
            print(utilities.PrintDecorations.colorize('OK', 'green'))

    def tail_metrics(self, pretty_print: Optional[bool] = True):
        """Tail and follow a metrics log to console
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
                    if metric.time.timestamp() not in visited:
                        visited.append(metric.time.timestamp())
                        if not pretty_print:
                            print(json.dumps(json.loads(str(metric)), indent=1))
                        else:
                            status_table = [
                                ['Time', 'Memory Allocated', 'Read (Bytes)',
                                 'Write (Bytes)', 'Open Files', 'Active Events', 'Published Events'],
                                [metric.time, metric.memory_allocated, metric.read_bytes,
                                 metric.write_bytes, metric.open_file_handles, metric.active_events,
                                 metric.published_events]
                            ]
                            print(tabulate.tabulate(status_table, tablefmt='fancy_grid'))
                    if len(visited) > 100:
                        visited = []
                start = datetime.utcnow() - timedelta(seconds=60)
                time.sleep(5)
        except KeyboardInterrupt:
            print(utilities.PrintDecorations.colorize('OK', 'green'))
