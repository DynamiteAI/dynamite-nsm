@load ./main
@load base/utils/directions-and-hosts

module Netbase;

export {       
	redef record Netbase::observation += {
        weirds_sent: count &default=0 &log;
        weirds_recvd: count &default=0 &log;
    };
}

event Weird::log_weird(rec: Weird::Info)
    {
    local orig = 0.0.0.0;
    local resp = 0.0.0.0;
    local pkg = observables();

    if ( rec?$conn ) 
		{
        orig = rec$conn$id$orig_h;
        resp = rec$conn$id$resp_h;
		}
	else if ( rec?$id )
		{
		orig = rec$id$orig_h;
        resp = rec$id$resp_h;
		}
	else 
		{
		return;
		}

    if ( addr_matches_host(orig, LOCAL_HOSTS) )
            {
            pkg[orig] = set([$name="weirds_sent"]);
            }
    if ( addr_matches_host(orig, LOCAL_HOSTS) )
            {
            pkg[resp] = set([$name="weirds_recvd"]);
            }
    }

# Handler to load observables into the observations table
# This event is executed every time a node calls the SEND()
# function.  Proxies only in cluster mode.  
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
event Netbase::add_observables(ip: addr, obs: set[observable])
    {
    for ( o in obs )
        {
        switch o$name
            {
            case "weirds_sent":
                ++observations[ip]$weirds_sent;
                break;
            case "weirds_recvd":
                ++observations[ip]$weirds_recvd;
                break;
            }       
        }
    }
@endif