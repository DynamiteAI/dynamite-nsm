## Usage

```bash
usage: [-h] [--log-sample-size LOG_SAMPLE_SIZE] [--pretty-print]

Suricata Main Log - View Suricata Internal error/warning/info messages.

optional arguments:
  -h, --help            show this help message and exit
  --log-sample-size LOG_SAMPLE_SIZE
                        The maximum number of entries (or lines) to parse
  --pretty-print        Print the log entry in a nice tabular view

```


## Sample Output
```json
[
  {
    "time": "2021-03-16 01:55:56.220000",
    "log_level": "WARN",
    "category": "engine",
    "error_code": 306,
    "error": "SC_WARN_FLOWBIT",
    "message": "flowbit 'ET.JS.Obfus.Func' is checked but not set. Checked in 2017247 and 0 other sigs"
  }
  {
    "time": "2021-03-16 01:55:59.980000",
    "log_level": "NOTICE",
    "category": "engine",
    "error_code": 0,
    "error": null,
    "message": "all 48 packet processing threads, 4 management threads initialized, engine started."
  }
]
```