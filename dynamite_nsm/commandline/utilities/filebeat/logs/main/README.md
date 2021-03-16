## Usage

```bash
usage:  main [-h] [--log-sample-size LOG_SAMPLE_SIZE] [--include-json-payloads] [--pretty-print]

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
    "time": "2021-03-10 03:03:02.300000",
    "log_level": "INFO",
    "category": "harvester",
    "message": "input ticker stopped",
    "json_payload": false
  },
  {
    "time": "2021-03-10 03:03:02.300000",
    "log_level": "INFO",
    "category": "harvester",
    "message": "input ticker stopped",
    "json_payload": false
  },
  {
    "time": "2021-03-10 03:03:03.220000",
    "log_level": "INFO",
    "category": "monitoring",
    "message": "Non-zero metrics in the last 30s",
    "json_payload": true
  }
]
```