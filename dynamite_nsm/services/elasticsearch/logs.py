import json


class StatusEntry:
    """
    An entry from Elasticsearch's main "cluster" log;
    """

    def __init__(self, entry_raw: str):
        """
        Initialize Status Entry
        Args:
            entry_raw: A line item representing a single entry within the Filebeat log
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