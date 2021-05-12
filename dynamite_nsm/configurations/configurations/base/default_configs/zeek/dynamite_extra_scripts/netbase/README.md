# netbase
Netbase, short for Network Baseliner is a Zeek framework for recording quantitative observations about network device activity.  It uses an entity-based approach for capturing observations which are aggregated over a pre-defined time interval.  At the end of the interval, an observation record for each _monitored_ IP address is written to the netbase log stream.

Devices considered _monitored_ are configurable by redefining the `Netbase::monitoring_mode` variable and optionally by specifying subnets in the `Netbase::critical_assets` variable.  Any IP address belonging to a subnet defined in `Netbase::critical_assets` will always be monitored, regardless of the monitoring mode selected.  In addition, the following monitoring modes are available (as defined in the Netbase::mode enum):

* PRIVATE_NETS - Record observations for any IP within a non-routable RFC 1918 address range
* LOCAL_NETS - Record observations for any IP within a Site::local_nets subnet 
* LOCAL_AND_NEIGHBORS - Record observations for any IP within a Site:local_nets or Site::local_neighbors subnets




