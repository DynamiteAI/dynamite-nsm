---
title: logs
---

## Logs Selection

```bash
root@jamin-dev:~# dynamite zeek logs -h
usage: dynamite logs [-h] {broker,cluster,metrics,reporter} ...

positional arguments:
  {broker,cluster,metrics,reporter}
    broker              Peering status events between Zeek or Broker-enabled processes
    cluster             View Zeek connections between nodes within this Zeek cluster.
    metrics             Zeek metrics aggregated over a consistent time interval.
    reporter            View Zeek Internal error/warning/info messages.

optional arguments:
  -h, --help            show this help message and exit

```

## Broker Log

```bash
root@jamin-dev:~# dynamite zeek logs broker -h
usage: dynamite logs broker [-h] [--log-sample-size LOG_SAMPLE_SIZE] [--include-archived-logs] [--pretty-print]

optional arguments:
  -h, --help            show this help message and exit
  --log-sample-size LOG_SAMPLE_SIZE
                        The maximum number of log entries to load into memory
  --include-archived-logs
                        If True, include gzipped archive logs
  --pretty-print        Print the log entry in a nice tabular view

```

## Cluster Log

```bash
root@jamin-dev:~# dynamite zeek logs cluster -h
usage: dynamite logs cluster [-h] [--log-sample-size LOG_SAMPLE_SIZE] [--include-archived-logs] [--pretty-print]

optional arguments:
  -h, --help            show this help message and exit
  --log-sample-size LOG_SAMPLE_SIZE
                        The maximum number of log entries to load into memory
  --include-archived-logs
                        If True, include gzipped archive logs
  --pretty-print        Print the log entry in a nice tabular view

```

## Metrics

```bash
root@jamin-dev:~# dynamite zeek logs metrics -h
usage: dynamite logs metrics [-h] [--log-sample-size LOG_SAMPLE_SIZE] [--include-archived-logs] [--pretty-print]

optional arguments:
  -h, --help            show this help message and exit
  --log-sample-size LOG_SAMPLE_SIZE
                        The maximum number of log entries to load into memory
  --include-archived-logs
                        If True, include gzipped archive logs content
  --pretty-print        Print the log entry in a nice tabular view
root@jamin-dev:~#
```

## Reporter Log

```bash
root@jamin-dev:~# dynamite zeek logs reporter -h
usage: dynamite logs reporter [-h] [--log-sample-size LOG_SAMPLE_SIZE] [--include-archived-logs] [--pretty-print]

optional arguments:
  -h, --help            show this help message and exit
  --log-sample-size LOG_SAMPLE_SIZE
                        The maximum number of log entries to load into memory
  --include-archived-logs
                        If True, include gzipped archive logs content
  --pretty-print        Print the log entry in a nice tabular view

```