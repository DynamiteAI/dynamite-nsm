SURICATA_CONFIG = '''
%YAML 1.1
---

af-packet:
- cluster-id: 99
  cluster-type: cluster_flow
  interface: ens5
  threads: auto
app-layer:
  protocols:
    dcerpc:
      enabled: true
    dhcp:
      enabled: true
    dnp3:
      detection-ports:
        dp: 20000
      enabled: false
    dns:
      tcp:
        detection-ports:
          dp: 53
        enabled: true
      udp:
        detection-ports:
          dp: 53
        enabled: true
    enip:
      detection-ports:
        dp: 44818
        sp: 44818
      enabled: false
    ftp:
      enabled: true
    http:
      enabled: true
      libhtp:
        default-config:
          double-decode-path: false
          double-decode-query: false
          http-body-inline: auto
          personality: IDS
          request-body-inspect-window: 4kb
          request-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          response-body-decompress-layer-limit: 2
          response-body-inspect-window: 16kb
          response-body-limit: 100kb
          response-body-minimal-inspect-size: 40kb
          swf-decompression:
            compress-depth: 0
            decompress-depth: 0
            enabled: true
            type: both
        server-config: null
    ikev2:
      enabled: true
    imap:
      enabled: detection-only
    krb5:
      enabled: true
    modbus:
      detection-ports:
        dp: 502
      enabled: false
      stream-depth: 0
    msn:
      enabled: detection-only
    nfs:
      enabled: true
    ntp:
      enabled: true
    smb:
      detection-ports:
        dp: 139, 445
      enabled: true
    smtp:
      enabled: true
      inspected-tracker:
        content-inspect-min-size: 32768
        content-inspect-window: 4096
        content-limit: 100000
      mime:
        body-md5: false
        decode-base64: true
        decode-mime: true
        decode-quoted-printable: true
        extract-urls: true
        header-value-depth: 2000
    ssh:
      enabled: true
    tftp:
      enabled: true
    tls:
      detection-ports:
        dp: 443
      enabled: true
      ja3-fingerprints: true
asn1-max-frames: 256
classification-file: /etc/dynamite/suricata/rules/classification.config
coredump:
  max-dump: unlimited
decoder:
  teredo:
    enabled: true
default-log-dir: /var/log/dynamite/suricata/
default-rule-path: /etc/dynamite/suricata/rules
defrag:
  hash-size: 65536
  max-frags: 65535
  memcap: 32mb
  prealloc: true
  timeout: 60
  trackers: 65535
detect:
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  grouping: null
  inspection-recursion-limit: 3000
  prefilter:
    default: mpm
  profile: medium
  profiling:
    grouping:
      dump-to-disk: false
      include-mpm-stats: false
      include-rules: false
  sgh-mpm-context: auto
engine-analysis:
  rules: true
  rules-fast-pattern: true
flow:
  emergency-recovery: 30
  hash-size: 65536
  memcap: 128mb
  prealloc: 10000
flow-timeouts:
  default:
    bypassed: 100
    closed: 0
    emergency-bypassed: 50
    emergency-closed: 0
    emergency-established: 100
    emergency-new: 10
    established: 300
    new: 30
  icmp:
    bypassed: 100
    emergency-bypassed: 50
    emergency-established: 100
    emergency-new: 10
    established: 300
    new: 30
  tcp:
    bypassed: 100
    closed: 60
    emergency-bypassed: 50
    emergency-closed: 10
    emergency-established: 100
    emergency-new: 5
    established: 600
    new: 60
  udp:
    bypassed: 100
    emergency-bypassed: 50
    emergency-established: 100
    emergency-new: 10
    established: 300
    new: 30
host:
  hash-size: 4096
  memcap: 32mb
  prealloc: 1000
host-mode: auto
host-os-policy:
  bsd: []
  bsd-right: []
  hpux10: []
  hpux11: []
  irix: []
  linux: []
  macos: []
  old-linux: []
  old-solaris: []
  solaris: []
  vista: []
  windows:
  - 0.0.0.0/0
  windows2k3: []
legacy:
  uricontent: enabled
logging:
  default-log-level: notice
  outputs:
  - console:
      enabled: true
  - file:
      enabled: true
      filename: /var/dynamite/suricata/log/suricata/suricata.log
      level: info
  - syslog:
      enabled: false
      facility: local5
      format: '[%i] <%d> -- '
luajit:
  states: 128
mpm-algo: auto
outputs:
- eve-log:
    community-id: true
    community-id-seed: 0
    enabled: true
    filename: eve.json
    filetype: regular
    pcap-file: false
    types:
    - alert:
        tagged-packets: true
    - http:
        extended: true
    - dns:
        version: 2
    - tls:
        extended: true
    - files:
        force-magic: true
    - smtp:
        extended: true
    - nfs
    - smb
    - tftp
    - ikev2
    - krb5
    - dhcp:
        enabled: true
        extended: false
    - ssh
    - stats:
        deltas: false
        threads: false
        totals: true
    - flow
    xff:
      deployment: reverse
      enabled: false
      header: X-Forwarded-For
      mode: extra-data
- unified2-alert:
    enabled: false
    filename: unified2.alert
    xff:
      deployment: reverse
      enabled: false
      header: X-Forwarded-For
      mode: extra-data
- http-log:
    append: true
    enabled: false
    filename: http.log
- tls-log:
    append: true
    enabled: false
    filename: tls.log
- tls-store:
    enabled: false
- dns-log:
    append: true
    enabled: false
    filename: dns.log
- pcap-log:
    compression: none
    enabled: false
    filename: log.pcap
    honor-pass-rules: false
    limit: 1000mb
    max-files: 2000
    mode: normal
    use-stream-depth: false
- alert-debug:
    append: true
    enabled: false
    filename: alert-debug.log
- alert-prelude:
    enabled: false
    log-packet-content: false
    log-packet-header: true
    profile: suricata
- stats:
    append: true
    enabled: true
    filename: stats.log
    threads: false
    totals: true
- syslog:
    enabled: false
    facility: local5
- drop:
    append: true
    enabled: false
    filename: drop.log
- file-store:
    enabled: false
    version: 2
    xff:
      deployment: reverse
      enabled: false
      header: X-Forwarded-For
      mode: extra-data
- file-store:
    enabled: false
    force-filestore: false
    force-magic: false
    include-pid: false
    log-dir: files
- file-log:
    append: true
    enabled: false
    filename: files-json.log
    force-magic: false
- tcp-data:
    enabled: false
    filename: tcp-data.log
    type: file
- http-body-data:
    enabled: false
    filename: http-data.log
    type: file
- lua:
    enabled: false
    scripts: null
pcap:
- interface: eth0
- interface: eth0
pcap-file:
  checksum-checks: auto
pcre:
  match-limit: 3500
  match-limit-recursion: 1500
pfring:
- cluster-id: 99
  cluster-type: cluster_flow
  interface: eth0
  threads: auto
profiling:
  keywords:
    append: true
    enabled: true
    filename: keyword_perf.log
  locks:
    append: true
    enabled: false
    filename: lock_stats.log
  packets:
    append: true
    csv:
      enabled: false
      filename: packet_stats.csv
    enabled: true
    filename: packet_stats.log
  pcap-log:
    append: true
    enabled: false
    filename: pcaplog_stats.log
  prefilter:
    append: true
    enabled: true
    filename: prefilter_perf.log
  rulegroups:
    append: true
    enabled: true
    filename: rule_group_perf.log
  rules:
    append: true
    enabled: true
    filename: rule_perf.log
    json: true
    limit: 10
reference-config-file: /etc/dynamite/suricata/reference.config
rule-files:
- botcc.rules
- botcc.portgrouped.rules
- ciarmy.rules
- compromised.rules
- dshield.rules
- emerging-attack_response.rules
- emerging-chat.rules
- emerging-current_events.rules
- emerging-dns.rules
- emerging-dos.rules
- emerging-exploit.rules
- emerging-ftp.rules
- emerging-imap.rules
- emerging-malware.rules
- emerging-misc.rules
- emerging-mobile_malware.rules
- emerging-netbios.rules
- emerging-policy.rules
- emerging-rpc.rules
- emerging-smtp.rules
- emerging-snmp.rules
- emerging-sql.rules
- emerging-trojan.rules
- emerging-user_agents.rules
- emerging-web_client.rules
- emerging-web_server.rules
- emerging-worm.rules
- tor.rules
spm-algo: auto
stats:
  decoder-events-prefix: decoder.event
  enabled: true
  interval: 8
stream:
  checksum-validation: true
  inline: auto
  memcap: 64mb
  reassembly:
    depth: 1mb
    memcap: 256mb
    randomize-chunk-size: true
    toclient-chunk-size: 2560
    toserver-chunk-size: 2560
threading:
  cpu-affinity:
  - management-cpu-set:
      cpu:
      - 0
  - receive-cpu-set:
      cpu:
      - 0
  - worker-cpu-set:
      cpu:
      - all
      mode: exclusive
      prio:
        default: medium
        high:
        - 3
        low:
        - 0
        medium:
        - 1-2
  detect-thread-ratio: 1.0
  set-cpu-affinity: false
unix-command:
  enabled: auto
vars:
  address-groups:
    AIM_SERVERS: $EXTERNAL_NET
    DC_SERVERS: $HOME_NET
    DNP3_CLIENT: $HOME_NET
    DNP3_SERVER: $HOME_NET
    DNS_SERVERS: $HOME_NET
    ENIP_CLIENT: $HOME_NET
    ENIP_SERVER: $HOME_NET
    EXTERNAL_NET: '!$HOME_NET'
    HOME_NET: '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]'
    HTTP_SERVERS: $HOME_NET
    MODBUS_CLIENT: $HOME_NET
    MODBUS_SERVER: $HOME_NET
    SMTP_SERVERS: $HOME_NET
    SQL_SERVERS: $HOME_NET
    TELNET_SERVERS: $HOME_NET
  port-groups:
    DNP3_PORTS: 20000
    FILE_DATA_PORTS: '[$HTTP_PORTS,110,143]'
    FTP_PORTS: 21
    HTTP_PORTS: '80'
    MODBUS_PORTS: 502
    ORACLE_PORTS: 1521
    SHELLCODE_PORTS: '!80'
    SSH_PORTS: 22
vlan:
  use-for-tracking: true
'''