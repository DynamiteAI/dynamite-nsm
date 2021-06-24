## Usage

```bash
usage: config main [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--verbose] [--stdout] [--out-file-path OUT_FILE_PATH] [--backup-directory BACKUP_DIRECTORY] [--top-text TOP_TEXT] [--home-net HOME_NET] [--external-net EXTERNAL_NET] [--http-servers HTTP_SERVERS] [--sql-servers SQL_SERVERS]
                   [--dns-servers DNS_SERVERS] [--telnet-servers TELNET_SERVERS] [--aim-servers AIM_SERVERS] [--dc-servers DC_SERVERS] [--modbus-client MODBUS_CLIENT] [--modbus-server MODBUS_SERVER] [--enip-client ENIP_CLIENT] [--enip-server ENIP_SERVER] [--http-ports HTTP_PORTS]
                   [--shellcode-ports SHELLCODE_PORTS] [--oracle-ports ORACLE_PORTS] [--ssh-ports SSH_PORTS] [--dnp3-ports DNP3_PORTS] [--modbus-ports MODBUS_PORTS] [--ftp-ports FTP_PORTS] [--file-data-ports FILE_DATA_PORTS] [--default-log-directory DEFAULT_LOG_DIRECTORY]
                   [--suricata-log-output-file SURICATA_LOG_OUTPUT_FILE] [--default-rules-directory DEFAULT_RULES_DIRECTORY] [--classification-file CLASSIFICATION_FILE] [--reference-config-file REFERENCE_CONFIG_FILE] [--suricata-config-file SURICATA_CONFIG_FILE]
                   {rules} ...

positional arguments:
  {rules}
    rules

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
                        The path to the Suricata configuration directory
  --verbose
  --stdout
  --out-file-path OUT_FILE_PATH
                        The path to the output file; if none given overwrites existing
  --backup-directory BACKUP_DIRECTORY
                        The path to the backup directory
  --top-text TOP_TEXT   The text to be appended at the top of the config file (typically used for YAML version header)

configuration options:
  --home-net HOME_NET
  --external-net EXTERNAL_NET
  --http-servers HTTP_SERVERS
  --sql-servers SQL_SERVERS
  --dns-servers DNS_SERVERS
  --telnet-servers TELNET_SERVERS
  --aim-servers AIM_SERVERS
  --dc-servers DC_SERVERS
  --modbus-client MODBUS_CLIENT
  --modbus-server MODBUS_SERVER
  --enip-client ENIP_CLIENT
  --enip-server ENIP_SERVER
  --http-ports HTTP_PORTS
  --shellcode-ports SHELLCODE_PORTS
  --oracle-ports ORACLE_PORTS
  --ssh-ports SSH_PORTS
  --dnp3-ports DNP3_PORTS
  --modbus-ports MODBUS_PORTS
  --ftp-ports FTP_PORTS
  --file-data-ports FILE_DATA_PORTS
  --default-log-directory DEFAULT_LOG_DIRECTORY
  --suricata-log-output-file SURICATA_LOG_OUTPUT_FILE
  --default-rules-directory DEFAULT_RULES_DIRECTORY
  --classification-file CLASSIFICATION_FILE
  --reference-config-file REFERENCE_CONFIG_FILE
  --suricata-config-file SURICATA_CONFIG_FILE
```

### Sub-Configurations Interface

#### Rules

```bash
usage: config main rules [-h] [--id {8213,9254,12647,11428,1407,14175,6923,2005,11428,858,147,8970,9983,8284,11902,8841,11709,2473,159,8709,10863,1938,8385,3187,9829,4409,14971,8179,4933,11939,13217,4033,4642,6927,4108,14312,2857,9007}] [--enable] [--disable]

optional arguments:
  -h, --help            show this help message and exit
  --id {8213,9254,12647,11428,1407,14175,6923,2005,11428,858,147,8970,9983,8284,11902,8841,11709,2473,159,8709,10863,1938,8385,3187,9829,4409,14971,8179,4933,11939,13217,4033,4642,6927,4108,14312,2857,9007}
                        Specify the id for the config object you want to work with.
  --enable              Enable selected object.
  --disable             Disable selected object

```


## Examples

```bash

$ python3 suricata/config/main

╒══════════════════════════╤════════════════════════════════════════════════════╕
│ Config Option            │ Value                                              │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ rules                    │ Configuration Module                               │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ home_net                 │ [192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ external_net             │ !$HOME_NET                                         │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ http_servers             │ $HOME_NET                                          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ sql_servers              │ $HOME_NET                                          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ dns_servers              │ $HOME_NET                                          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ telnet_servers           │ $HOME_NET                                          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ aim_servers              │ $EXTERNAL_NET                                      │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ dc_servers               │ $HOME_NET                                          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ modbus_client            │ $HOME_NET                                          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ modbus_server            │ $HOME_NET                                          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ enip_client              │ $HOME_NET                                          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ enip_server              │ $HOME_NET                                          │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ http_ports               │ 80                                                 │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ shellcode_ports          │ !80                                                │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ oracle_ports             │ 1521                                               │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ ssh_ports                │ 22                                                 │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ dnp3_ports               │ 20000                                              │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ modbus_ports             │ 502                                                │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ ftp_ports                │ 21                                                 │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ file_data_ports          │ [$HTTP_PORTS,110,143]                              │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ default_log_directory    │ /opt/dynamite/suricata/logs                        │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ suricata_log_output_file │ /opt/dynamite/suricata/logs/suricata.log           │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ default_rules_directory  │ /etc/dynamite/suricata/rules                       │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ classification_file      │ /etc/dynamite/suricata/rules/classification.config │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ reference_config_file    │ /etc/dynamite/suricata/reference.config            │
├──────────────────────────┼────────────────────────────────────────────────────┤
│ suricata_config_file     │ /etc/dynamite/suricata/suricata.yaml               │
╘══════════════════════════╧════════════════════════════════════════════════════╛

```

```bash
$ python3 suricata/config/main rules

╒═══════╤════════════════════════════════╤═════════╤═══════╕
│ Id    │ Name                           │ Enabled │ Value │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 8213  │ botcc.rules                    │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 9254  │ botcc.portgrouped.rules        │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 12647 │ ciarmy.rules                   │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 11428 │ compromised.rules              │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 1407  │ drop.rules                     │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 14175 │ dshield.rules                  │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 6923  │ emerging-attack_response.rules │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 2005  │ emerging-chat.rules            │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 11428 │ emerging-current_events.rules  │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 858   │ emerging-dns.rules             │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 147   │ emerging-dos.rules             │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 8970  │ emerging-exploit.rules         │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 9983  │ emerging-ftp.rules             │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 8284  │ emerging-imap.rules            │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 11902 │ emerging-malware.rules         │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 8841  │ emerging-misc.rules            │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 11709 │ emerging-mobile_malware.rules  │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 2473  │ emerging-netbios.rules         │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 159   │ emerging-p2p.rules             │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 8709  │ emerging-policy.rules          │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 10863 │ emerging-pop3.rules            │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 1938  │ emerging-rpc.rules             │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 8385  │ emerging-smtp.rules            │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 3187  │ emerging-snmp.rules            │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 9829  │ emerging-sql.rules             │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 4409  │ emerging-telnet.rules          │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 14971 │ emerging-tftp.rules            │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 8179  │ emerging-trojan.rules          │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 4933  │ emerging-user_agents.rules     │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 11939 │ emerging-voip.rules            │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 13217 │ emerging-web_client.rules      │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 4033  │ emerging-web_server.rules      │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 4642  │ emerging-worm.rules            │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 6927  │ tor.rules                      │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 4108  │ http-events.rules              │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 14312 │ smtp-events.rules              │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 2857  │ dns-events.rules               │ True    │ N/A   │
├───────┼────────────────────────────────┼─────────┼───────┤
│ 9007  │ tls-events.rules               │ True    │ N/A   │
╘═══════╧════════════════════════════════╧═════════╧═══════╛

```