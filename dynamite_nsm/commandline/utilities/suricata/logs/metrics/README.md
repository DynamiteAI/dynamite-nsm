## Usage

```bash
usage: metrics [-h] [--log-sample-size LOG_SAMPLE_SIZE] [--pretty-print]

Suricata Aggregated Metrics - Suricata metrics aggregated over a consistent time interval.

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
    "timestamp": "2021-03-16 03:00:40",
    "time": "2021-03-16 03:00:40",
    "uptime": null,
    "capture_kernel_packets": 26,
    "capture_kernel_drops": 0,
    "capture_kernel_drops_percentage": 0.0,
    "capture_errors": 0,
    "flow_memory": 7240175,
    "tcp_memory": 6881280,
    "tcp_reassembly_memory": 1179648,
    "dns_memory": 0,
    "http_memory": 0,
    "ftp_memory": 0,
    "total_memory": 15301103,
    "http_events": 0,
    "tls_events": 0,
    "ssh_events": 0,
    "imap_events": 0,
    "msn_events": 0,
    "smb_events": 0,
    "dcerpc_tcp_events": 0,
    "dns_tcp_events": 0,
    "nfs_tcp_events": 0,
    "ntp_events": 0,
    "ftp_data_events": 0,
    "tftp_events": 0,
    "ikev2_data_events": 0,
    "krb5_tcp_events": 0,
    "dhcp_events": 0,
    "failed_tcp_events": 0,
    "dcerpc_udp_events": 6,
    "dns_udp_events": 3,
    "krb5_udp_events": 0,
    "failed_udp_events": 6
  }
  {
    "timestamp": "2021-03-16 03:00:48",
    "time": "2021-03-16 03:00:48",
    "uptime": null,
    "capture_kernel_packets": 22,
    "capture_kernel_drops": 0,
    "capture_kernel_drops_percentage": 0.0,
    "capture_errors": 0,
    "flow_memory": 7239824,
    "tcp_memory": 6881280,
    "tcp_reassembly_memory": 1179648,
    "dns_memory": 0,
    "http_memory": 0,
    "ftp_memory": 0,
    "total_memory": 15300752,
    "http_events": 0,
    "tls_events": 0,
    "ssh_events": 0,
    "imap_events": 0,
    "msn_events": 0,
    "smb_events": 0,
    "dcerpc_tcp_events": 0,
    "dns_tcp_events": 0,
    "nfs_tcp_events": 0,
    "ntp_events": 0,
    "ftp_data_events": 0,
    "tftp_events": 0,
    "ikev2_data_events": 0,
    "krb5_tcp_events": 0,
    "dhcp_events": 0,
    "failed_tcp_events": 0,
    "dcerpc_udp_events": 2,
    "dns_udp_events": 3,
    "krb5_udp_events": 0,
    "failed_udp_events": 2
  }
]


```