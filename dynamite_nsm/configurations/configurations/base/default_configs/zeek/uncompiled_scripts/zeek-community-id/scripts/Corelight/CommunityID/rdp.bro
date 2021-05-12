@ifdef (RDP::Info)
export {
    redef record RDP::Info += {
        community_id: string &optional &log;
    };
}

event rdp_connect_request(c: connection, cookie: string)
    {
    if ( ! c$rdp?$community_id && c?$community_id )
        c$rdp$community_id = c$community_id;       
    }

event rdp_negotiation_failure(c: connection, failure_code: count)
    {
    if ( ! c$rdp?$community_id && c?$community_id )
        c$rdp$community_id = c$community_id;
    }

event rdp_negotiation_response(c: connection, security_protocol: count)
    {
    if ( ! c$rdp?$community_id && c?$community_id )
        c$rdp$community_id = c$community_id;
    }
@endif

