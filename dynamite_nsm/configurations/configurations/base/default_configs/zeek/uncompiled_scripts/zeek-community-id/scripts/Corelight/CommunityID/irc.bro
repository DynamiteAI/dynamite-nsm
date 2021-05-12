@ifdef (IRC::Info)

export {
    redef record IRC::Info += {
        community_id: string &optional &log;
    };
}
event irc_request(c: connection, is_orig: bool, prefix: string, command: string, arguments: string)
    {
    if ( ! c$irc?$community_id && c?$community_id )
        c$irc$community_id = c$community_id;
    }

event irc_reply(c: connection, is_orig: bool, prefix: string, code: count, params: string)
    {
    if ( ! c$irc?$community_id && c?$community_id )
        c$irc$community_id = c$community_id;
    }

@endif
