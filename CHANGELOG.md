## Releases

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
