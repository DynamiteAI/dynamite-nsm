@load ./main
@load base/utils/directions-and-hosts
@load base/protocols/dns

module Netbase;

export {
    redef record Netbase::observation += {
        # DNS observables
        dns_as_client: count &default=0 &log;
        dns_as_server: count &default=0 &log;
        dns_auth_answers: count &default=0 &log;
        dns_recur_answers: count &default=0 &log;
        dns_ext_rrs: count &default=0 &log;
        dns_ext_rr_cnt: count &default=0 &log;
        dns_int_rrs: count &default=0 &log;
        dns_int_rr_cnt: count &default=0 &log;
        dns_nxdomain_rcvd: count &default=0 &log;
        dns_nxdomain_sent: count &default=0 &log;
        dns_rej_sent: count &default=0 &log;
        dns_rej_rcvd: count &default=0 &log;
    };
}

# Handle the final log_dns event
event DNS::log_dns(req: DNS::Info)
    {
    local orig = rec$id$orig_h;
    local resp = rec$id$resp_h;

    local pkg = observables();

    if ( addr_matches_host(orig, LOCAL_HOSTS) && /^255\.|\.255$/ !in cat(orig) )
        pkg[orig] = set([$name="dns_as_client"]);        
        
        if ( rec?$qtype )
            pkg[orig] = set([$name="dns_ext_rrs", $val=rec$qtype]);


    if ( addr_matches_host(resp, LOCAL_HOSTS) && /^255\.|\.255$/ !in cat(resp) )
        pkg[resp] = set([$name="dns_as_server"]);

        if ( rec?$AA && rec$AA == T && rec$rcode = 0 )
            add pkg[resp][["dns_auth_answers"]];

        else if ( rec?$AA && rec$AA == F && rec$rcode = 0 )
            add pkg[resp][["dns_recur_answers"]];


pkg[resp] = set([$name="dns_int_rrs"
pkg[resp] = set([$name="dns_nxdomain_rcvd"
pkg[resp] = set([$name="dns_nxdomain_sent"
pkg[resp] = set([$name="dns_rej_sent"
pkg[resp] = set([$name="dns_rej_rcvd"

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
            case "http_post_sent"
                ++observations[ip]$http_post_sent;
            	break;
            case "http_post_recvd"
                ++observations[ip]$http_post_recvd;
            	break;
            case "http_get_sent"
                ++observations[ip]$http_get_sent;
                break;
            case "http_get_recvd"
                ++observations[ip]$http_get_recvd;
            	break;
            case "http_400_recvd"
                ++observations[ip]$http_400_recvd;
            	break;
            case "http_500_recvd"
                ++observations[ip]$http_500_recvd;
            	break;
            case "http_400_sent"
                ++observations[ip]$http_400_sent;
            	break;
            case "http_500_sent"
                ++observations[ip]$http_500_sent;
                break;
            }       
        }
    }
@endif
