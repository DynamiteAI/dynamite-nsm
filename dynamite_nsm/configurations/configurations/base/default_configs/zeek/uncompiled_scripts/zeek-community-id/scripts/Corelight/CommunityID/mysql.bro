@ifdef (MySQL::Info)
export {
    redef record MySQL::Info += {
        community_id: string &optional &log;
    };
}

event mysql_command_request(c: connection, command: count, arg: string)
    {
    if ( ! c$mysql?$community_id && c?$community_id )
        c$mysql$community_id = c$community_id;
    }

event mysql_error(c: connection, code: count, msg: string)
    {
    if ( ! c$mysql?$community_id && c?$community_id )
        c$mysql$community_id = c$community_id;
    }

event mysql_ok(c: connection, affected_rows: count)
    {
    if ( ! c$mysql?$community_id && c?$community_id )
        c$mysql$community_id = c$community_id;
    }
@endif
