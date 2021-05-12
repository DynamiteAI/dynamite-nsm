@ifdef (DNS::Info)

export {
# Add the ID to the DNS record 
    redef record DNS::Info += {
        community_id: string &optional &log;
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=-5
    {
    # new_connection is not being triggered for UDP, so we need another plan 
    if (! c$dns?$community_id && c?$community_id)
        c$dns$community_id = c$community_id;
    }

event dns_end(c: connection, msg: dns_msg)
    {
    if (! c$dns?$community_id && c?$community_id)
        c$dns$community_id = c$community_id;
    }

@endif