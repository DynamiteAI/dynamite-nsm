import json

from typing import Optional


class StatusEntry:
    """
    An entry from Elasticsearch's main "cluster" log;
    """

    def __init__(self, entry_raw: str):
        """
        :param entry_raw: A line item representing a single entry within the Filebeat log
        """

        self.entry_raw = entry_raw
        self.message = None
        self.category = None
        self.timestamp = None
        self.log_level = None
        self.time = None
        self._parse_entry()

    def _parse_entry(self) -> None:
        log_entry = self.entry_raw.replace("\n", "").split('[')
        print(log_entry)

    def __str__(self):
        log_entry = dict(
            time=str(self.time),
            log_level=self.log_level,
            category=self.category,
            message=self.message,
        )
        return json.dumps(log_entry)


StatusEntry('[2021-04-02T00:48:48,136][INFO ][c.a.o.j.s.JobSweeper     ] [dynamite_node] Running full sweep')