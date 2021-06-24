## Usage

```bash
usage:  metrics [-h] [--log-sample-size LOG_SAMPLE_SIZE] [--include-json-payloads] [--pretty-print]

optional arguments:
  -h, --help            show this help message and exit
  --log-sample-size LOG_SAMPLE_SIZE
                        The maximum number of entries to parse
  --include-json-payloads
                        If, True, then metrics payloads will be included in their raw JSON form
  --pretty-print        Print the log entry in a nice tabular view

```

## Sample Output

```json
[
  {
    "time": "2021-03-10 03:02:03.220000",
    "open_file_handles": 35,
    "memory_allocated": 54269920,
    "harvester_open_files": 24,
    "harvester_running_files": 0,
    "read_bytes": 0,
    "write_bytes": 0,
    "active_events": 8256,
    "published_events": 0
  },
  {
    "time": "2021-03-10 03:03:03.220000",
    "open_file_handles": 18,
    "memory_allocated": 55462736,
    "harvester_open_files": 7,
    "harvester_running_files": 0,
    "read_bytes": 0,
    "write_bytes": 0,
    "active_events": 4123,
    "published_events": 0
  }
]
```