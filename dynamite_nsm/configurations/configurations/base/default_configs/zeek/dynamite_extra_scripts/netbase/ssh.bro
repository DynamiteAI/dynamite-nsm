@load ./main
@load base/utils/directions-and-hosts
@load base/protocols/ssh

module Netbase;

export {
	redef record Netbase::observation += {
        # SSH Stats
        ssh_auth_fail_sent: count &default=0 &log;
        ssh_auth_fail_recvd: count &default=0 &log;
        ssh_as_client: count &default=0 &log;
        ssh_as_server: count &default=0 &log;
	};
}

# Collect ssh auth failure stats
event ssh_auth_failed(c: connection)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local pkg = observables();

    if ( addr_matches_host(orig, LOCAL_HOSTS) )
        {
        pkg[orig] = set([$name="ssh_auth_fail_recvd"]);
        }
    if ( addr_matches_host(resp, LOCAL_HOSTS) )
        {
        pkg[resp] = set([$name="ssh_auth_fail_sent"]);
        }

    # See if the observable pkgs need delivering
    if ( orig in pkg )
        {
        Netbase::SEND(orig, pkg[orig]);
        }

    if ( resp in pkg )
        {
        Netbase::SEND(resp, pkg[resp]);
        }
    }

# Handle auth success events to track when hosts are acting as 
# as ssh clients and servers. 
event ssh_auth_successful(c: connection, auth_method_none: bool) 
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local pkg = observables();

    if ( addr_matches_host(orig, LOCAL_HOSTS) )
        {
        pkg[orig] = set([$name="ssh_as_client"]);
        }
    if ( addr_matches_host(resp, LOCAL_HOSTS) )
        {
        pkg[resp] = set([$name="ssh_as_server"]);
        }

    # See if the observable pkgs need delivering
    if ( orig in pkg )
        {
        Netbase::SEND(orig, pkg[orig]);
        }

    if ( resp in pkg )
        {
        Netbase::SEND(resp, pkg[resp]);
        }
    }

# Handler to load observables into the observations table
# This event is executed every time a node calls the SEND()
# function.  
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
event Netbase::add_observables(ip: addr, obs: set[observable])
    {
    for ( o in obs )
        {
        switch o$name
            {
            case "ssh_auth_fail_recvd":
                ++observations[ip]$ssh_auth_fail_recvd;
                break;
            case "ssh_auth_fail_sent":
                ++observations[ip]$ssh_auth_fail_sent;
                break;
            case "ssh_as_client":
                ++observations[ip]$ssh_auth_fail_recvd;
                break;
            case "ssh_as_server":
                ++observations[ip]$ssh_auth_fail_sent;
                break;
            }       
        }
    }
@endif

