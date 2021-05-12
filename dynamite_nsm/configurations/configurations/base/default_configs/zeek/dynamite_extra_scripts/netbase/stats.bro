@load ./main

module Netbase_stats;

export {
	# Register the Log ID
    redef enum Log::ID += { LOG };

    # Record for logging observation table stats
    type stat_info: record {
        ts: time &log;
        node_id: string &log;
        addr_cnt: count &log;
        table_size: count &log;
        # addrs: set[addr] &log &optional;
    };

    # Log stats every stats_interval
    global stats_interval: interval = 1mins &redef;

    # Event for logging stats
    global log_stats: event(rec: stat_info);
}

event get_stats()
    {
    @if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY ) 
    local rec = stat_info(
		$ts = network_time(),
		$node_id = getenv("CLUSTER_NODE"),
		$addr_cnt = |Netbase::observations|,
		$table_size = val_size(Netbase::observations)
	);

#	rec$addrs = set();
#
#	for ( k in Netbase::observations ) 
#		{
#		add rec$addrs[k];
#		}
	
    Log::write(Netbase_stats::LOG, rec);

    schedule stats_interval { get_stats() };
    @endif
    }

event bro_init()
	{
	event get_stats();
	Log::create_stream(Netbase_stats::LOG, [$columns=stat_info, $ev=log_stats, $path="netbase_stats"]);
	}
    