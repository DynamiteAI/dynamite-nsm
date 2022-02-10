## Releases

### 1.1

#### New Features
- Most `dynamite` commands can now run as non-root users, provided that user is added to the `dynamite` group.
- `setup` command added to decouple environment preparation from individual service installation. Also provides the ability to fully uninstall NSM services. 
- `zeek reset`, `suricata reset`, and `filebeat reset` commands allows users to revert various configurations back to a default states.
- `suricata config `
- Zeek and Suricata now expose network interface settings to the `dynamite` commandline.
- `dynamite-remote` is now included by default with the `dynamite-nsm` package.
- Zeek Script and Suricata Ruleset ids are now generated via SHA1 content based hashing.
- `setcap` now runs before Zeek and Suricata processes are started, allowing them to capture traffic as non-root privileged users.
- `dynamite_nsm.services.base.systemctl` module now provides a `FallbackCtl` mode which currently allows agent processes to be managed inside a docker container.
- Added several docker examples for Dynamite Agent
- BPF validation binary now included as part of the package.
- Added friendly aliases and descriptive information for several new EmergingThreat Open rule-sets
- Added the [Log4Shell exploit detection](https://github.com/corelight/cve-2021-44228) script for Zeek by default.
- Improved exception handling across `dynamite_nsm` package.
- Updated to latest [default configurations](https://github.com/DynamiteAI/configurations/releases/tag/1.1.3)
- Installs Kibana `BaseViews` [0.4](https://github.com/DynamiteAI/kibana_packages)

#### Removed Features
- `dynamite remote` command has been replaced with `dynamite auth` to avoid confusion.
- `dynamite agent optimize` command no longer takes the parameter `--inspection-interfaces`
- Removed Suricata installer's WireShark dependency

#### Bugs
- Elasticsearch and Logstash will no longer over-allocate Java heap.
- Hard coded binary paths have been removed from NSM installed `.service` files.
- When installing NSM services on RHEL systems powertools and EPEL repos are first added.
- Addressed issued where Filebeat Kafka targets were pulling Redis host definitions


### 1.0

#### New Features
- Adds type-hints to all methods and functions.
- Greatly Simplified SDK
   - Added additional base service classes.
   - Simplified `*Manager` setup methods.
   - Replaced the `components` module with `cmd` module for building command-line utilities from `services` classes.
   - Removed tons of redundant code within `services`
- Introduced initial version of task framework for running various background jobs against services on the stack.
- Added several new commands
  - Added `agent optimize` command to automatically adjust threading/pinning settings within Zeek/Suricata
  - Added`logs` command to agent services for presenting relevant performance logs for Zeek and Suricata.
  - Added non-interactive interfaces for service `config` commands
  - Added `remote` command allowing a controller to remotely connect to this instance
  - Added `elasticsearch config users` command for resetting the passwords of internal users.
  - Running `dynamite` with no arguments now returns a status menu of all installable services.
#### Removed Features
- Removed Python2 support; Python3.7+ only!
- Removed ElastiFlow & Synesis dependency.
- Logstash is now an optional dependency
- Removed configuration TUIs in favor of simplified commandline interfaces
- Dynamite `lab` and `daemon` services has been temporarily retired, and will be available in later a later release

#### Bugs

- Addressed some issues with patch_modules command not running properly when either Zeek/Suricata had not been installed
- Addressed several permission issues when installing agent components

---
## Pre Releases

### 0.8.0

- Created several `log` wrapper classes for Zeek, Suricata, and FIlebeat, providing easy access to several logs needed for troubleshooting.
  - Implements [linecache](https://docs.python.org/2/library/linecache.html) module for more efficient readIO against large log files.
  - Provides basic search functionality such as basic timeframe querying and return limits.
- Added `patch_modules` install method for Filebeat, allowing for ECS normalization of Zeek and Suricata logs.
  - Added corresponding enable/disable methods for toggling on and off
- Exposed Filebeat SSL/TLS options for all supported outputs.
- Adds a `LocalNetworkConfigManager` for Zeek, which allows access to the `etc/network.cfg`, used to specify local networks to Zeek.
- `suricata_log_output_file` now passed through to the `SuricataConfigManager`
  - Updated logic to handle parsing lists of dictionaries in addition to nested dictionaries.
- Moved suricata default logging directory to `/opt/dynamite/suricata/logs/` which avoids the mess created when lower runlevel ops try to write to `/var/` before it is mounted.
- move to jemalloc for Zeek/Suricata compiling

### 0.7.2

- Zeek 3.0.3 support
- Adds dynamited service and component
  - [dynamited_core](https://github.com/DynamiteAI/dynamite_daemon_core)
  - [dynamited_pub](https://github.com/DynamiteAI/dynamited_pub)
- Enhancements to service modules; base service modules introduced.
- Enhancements to default configurations.
- Enhancements to systemd integration
   - stdout/stderr passthrough
   - exit status
   - running status
- Commandline statuses now pretty-print by default

### 0.7.1

- AF_PACKET replaces PF_RING for Zeek
   - No reboot required on agent install
   - Improved compile times
- Systemd replaces the builtin process manager for agent
- Community_ID supported across Zeek application logs
- Improved OS support
- Defaulted ES templates to 0 replicas 1 shard (most common installation)

### 0.7.0

- Brand new [command-line](https://dynamite-nsm.readthedocs.io/en/latest/getting_started/cmd_overview/)
  - nested help modules
- Community_id now added to both Zeek and Suricata (agent logs only for now)
- Breaks up service modules into submodules
  - install - manage service installation/uninstallation/initial configuration
  - config - manage service configuration
  - process - manage service processes
  - profile - monitor service processes
- Adds custom exception handling install/config functions no longer return booleans on failure, but rather raise exceptions
- Adds logger
- Improves Download/Process tracking interfaces
- Adds new Filebeat terminal UI
- Adds new agent config terminal UI
- ReadTheDocs documentation [added](https://dynamite-nsm.readthedocs.io/en/latest/)
- Adds config module unit tests
