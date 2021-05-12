@ifdef (SOCKS::Info)

export {
    redef record SOCKS::Info += {
        community_id: string &optional &log;
    };
}

event socks_reply(c: connection, version: count, reply: count, sa: SOCKS::Address, p: port)
    {
    if ( ! c$socks?$community_id && c?$community_id )
        c$socks$community_id = c$community_id;
    }

event socks_request(c: connection, version: count, request_type: count, sa: SOCKS::Address, p: port, user: string)
    {
    if ( ! c$socks?$community_id && c?$community_id )
        c$socks$community_id = c$community_id;
    }
@endif