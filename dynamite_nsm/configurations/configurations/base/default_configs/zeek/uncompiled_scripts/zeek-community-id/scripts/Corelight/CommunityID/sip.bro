@ifdef (SIP::Info)
export {
    redef record SIP::Info += {
        community_id: string &optional &log;
    };
}

event sip_reply(c: connection, version: string, code: count, reason: string)
    {
    if ( ! c$sip?$community_id && c?$community_id )
        c$sip$community_id = c$community_id;
    }

event sip_request(c: connection, method: string, original_URI: string, version: string)
    {
    if ( ! c$sip?$community_id && c?$community_id )
        c$sip$community_id = c$community_id;
    }
@endif