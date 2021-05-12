# Adds the orientation field to zeek conn log.  
# Orientation is merely a way to describe the hosts/networks
# involved in the communication, and how it was initiated.  

# Note:: Update Site::local_nets and Site::neighbor_nets 
# for this to be as accurrate as possible.  
module Site;

export {
    redef record Conn::Info += {
        orientation: string &log &optional;
    };
}

function get_oriented(id: conn_id): string
    {
    local o = "";
    local r = "";

    # test orig 
    if ( Site::is_local_addr(id$orig_h) )
        o = "local";
    else if ( Site::is_neighbor_addr(id$orig_h))
        o = "neighbor";
    else 
        o = "external";

    # test resp 
    if ( Site::is_local_addr(id$resp_h) )
        r = "local";
    else if ( Site::is_neighbor_addr(id$resp_h))
        r = "neighbor";
    else if ( id$resp_h in 224.0.0.0/4 )
        r = "multicast";    
    else if ( /^255\./ in cat(id$resp_h) || /\.255$/ in cat(id$resp_h) )
        r = "broadcast";    
    else 
        r = "external";

    # now evaluate 
    if ( o == "local" && r == "local" )
        return "internal";
    else if ( o == "local" && r == "external" )
        return "egress";
    else if ( o == "external" && r == "local" )
        return "ingress";
    else if ( o == "external" && r == "external" )
        return "external";
    else if ( o == "local" && r == "neighbor" ) 
        return "to_neighbor";
    else if ( o == "neighbor" && r == "local" )
        return "from_neighbor";
    else if ( o == "local" && r == "multicast")
        return "multicast";
    else if ( o == "local" && r == "broadcast")
        return "broadcast";
    else 
        return "unknown";
    }

event connection_state_remove(c: connection) 
    {
    # 
    c$conn$orientation = get_oriented(c$id);
    }