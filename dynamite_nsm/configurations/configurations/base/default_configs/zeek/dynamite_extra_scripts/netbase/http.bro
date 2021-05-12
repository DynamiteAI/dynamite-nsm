@load ./main
@load base/utils/directions-and-hosts
@load base/protocols/http

module Netbase;

export {
    redef record Netbase::observation += {
        # HTTP observations
        http_post_sent: count &default=0 &log;
        http_post_recvd: count &default=0 &log;
        http_get_sent: count &default=0 &log;
        http_get_recvd: count &default=0 &log;
        http_400_recvd: count &default=0 &log;
        http_500_recvd: count &default=0 &log;
        http_400_sent: count &default=0 &log;
        http_500_sent: count &default=0 &log;
    };
}

# Collect http request stats 
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    local pkg = observables();

    switch method
        {
        case "POST":
            if ( addr_matches_host(orig, LOCAL_HOSTS) )
                pkg[orig] = set([$name="http_post_sent"]);        

            if ( addr_matches_host(resp, LOCAL_HOSTS) )
                pkg[resp] = set([$name="http_post_recvd"]);

            break;
        case "GET":
            # do something 
            if ( addr_matches_host(orig, LOCAL_HOSTS) )
                pkg[orig] = set([$name="http_get_sent"]);        
                
            if ( addr_matches_host(resp, LOCAL_HOSTS) )
                pkg[resp] = set([$name="http_get_recvd"]);
            
            break;
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

# Collect HTTP server response stats 
event http_reply(c: connection, version: string, code: count, reason: string)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    local pkg = observables();

    # check for client-generated errors
    if ( /^4/ in cat(code))
        {
        if ( addr_matches_host(orig, LOCAL_HOSTS) )
                pkg[orig] = set([$name="http_400_recvd"]);        

        if ( addr_matches_host(resp, LOCAL_HOSTS) )
                pkg[resp] = set([$name="http_400_sent"]);
        }
    # check for server-side errors
    else if ( /^5/ in cat(code))
        {
        if ( addr_matches_host(orig, LOCAL_HOSTS) )
                pkg[orig] = set([$name="http_500_recvd"]);   

        if ( addr_matches_host(resp, LOCAL_HOSTS) )
                pkg[resp] = set([$name="http_500_sent"]);
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
            case "http_post_sent":
                ++observations[ip]$http_post_sent;
            	break;
            case "http_post_recvd":
                ++observations[ip]$http_post_recvd;
            	break;
            case "http_get_sent":
                ++observations[ip]$http_get_sent;
                break;
            case "http_get_recvd":
                ++observations[ip]$http_get_recvd;
            	break;
            case "http_400_recvd":
                ++observations[ip]$http_400_recvd;
            	break;
            case "http_500_recvd":
                ++observations[ip]$http_500_recvd;
            	break;
            case "http_400_sent":
                ++observations[ip]$http_400_sent;
            	break;
            case "http_500_sent":
                ++observations[ip]$http_500_sent;
                break;
            }       
        }
    }
@endif
