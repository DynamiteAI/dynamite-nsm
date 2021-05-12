@load policy/tuning/json-logs
@load misc/loaded-scripts
@load tuning/defaults
@load misc/capture-loss
@load misc/stats

# Signatures
@load-sigs frameworks/signatures/detect-windows-shells


# Load the scan detection script.
@load misc/scan

# Conn Protocol Scripts
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging

# FTP Protocol Scripts
@load protocols/ftp/detect
@load protocols/ftp/software
@load protocols/ftp/detect-bruteforcing

# DHCP Protocol Scripts
@load protocols/dhcp/msg-orig
@load protocols/dhcp/software
@load protocols/dhcp/sub-opts

# DNS Protocol Scripts
@load protocols/dns/auth-addl
@load protocols/dns/detect-external-names

# HTTP Protocol Scripts
@load protocols/http/detect-sqli
@load protocols/http/detect-webapps
@load protocols/http/header-names
# @load protocols/http/software-browser-plugins
# @load protocols/http/software
# @load protocols/http/var-extraction-cookies
@load protocols/http/var-extraction-uri

# Kerberos Protocol Scripts
@load protocols/krb/ticket-logging

# Modbus Protocol Scripts
# @load protocols/modbus/known-masters-slaves
# @load protocols/modbus/track-memmap

# Mysql Protocol Scripts
# @load protocols/mysql/software

# RDP Protocol Scripts
@load protocols/rdp/indicate_ssl

# SMB Protocol Scripts
@load protocols/smb/log-cmds

# SMTP Protocol Scripts
@load protocols/smtp/blocklists
@load protocols/smtp/detect-suspicious-orig
@load protocols/smtp/entities-excerpt
@load protocols/smtp/software

# SSH Protocol Scripts
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/geo-data
@load protocols/ssh/interesting-hostnames
@load protocols/ssh/software

# SSL Protocol Scripts
@load protocols/ssl/expiring-certs
@load protocols/ssl/extract-certs-pem
@load protocols/ssl/heartbleed
@load protocols/ssl/known-certs
# @load protocols/ssl/log-hostcerts-only
@load protocols/ssl/notary
@load protocols/ssl/validate-ocsp
@load protocols/ssl/validate-sct
@load protocols/ssl/weak-keys

# Dynamic Protocol Detection Framework
@load frameworks/dpd/detect-protocols
@load frameworks/dpd/packet-segment-logging

# Files Framework
@load frameworks/files/detect-MHR
@load frameworks/files/entropy-test-all-files
# @load frameworks/files/extract-all-files
@load frameworks/files/hash-all-files

# Plugins
@load Corelight/CommunityID
@load Zeek_AF_Packet/scripts

# Notice Framework
@load policy/frameworks/notice/extend-email/hostnames

redef ignore_checksums = T;
redef Stats::report_interval = 1 mins;
redef Netbase::obs_interval = 5 mins;