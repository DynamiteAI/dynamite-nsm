@load ./main
@load base/utils/directions-and-hosts
@load base/protocols/ftp

module Netbase;

export {
    # FTP stats
    redef record Netbase::observation += {
        ftp_auth_failures: count &default=0 &log;
        ftp_failed_auth_attempts: count &default=0 &log;
    };
}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local pkg = observables();;
    local cmd = c$ftp$cmdarg$cmd;

    if ( cmd == "USER" || cmd == "PASS" )
        {
        if ( FTP::parse_ftp_reply_code(code)$x == 5 )
            {
            if ( addr_matches_host(orig, LOCAL_HOSTS) )
                {
                pkg[orig] = set([$name="ftp_failed_auth_attempts"]); 
                }

            if ( addr_matches_host(resp, LOCAL_HOSTS) )
                {
                pkg[resp] = set([$name="ftp_auth_failures"]); 
                }
            }
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
            case "ftp_failed_auth_attempts":
                ++observations[ip]$ftp_failed_auth_attempts;
                break;
            case "ftp_auth_failures":
                ++observations[ip]$ftp_auth_failures;
                break;
            }       
        }
    }
@endif