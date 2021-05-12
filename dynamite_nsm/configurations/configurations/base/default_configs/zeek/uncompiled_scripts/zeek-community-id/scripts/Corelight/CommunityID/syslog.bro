@ifdef (Syslog::Info)
export {
    redef record Syslog::Info += {
        community_id: string &optional &log;
    };
}

event syslog_message(c: connection, facility: count, severity: count, msg: string)
    {
    if ( !c$syslog?$community_id && c?$community_id )
        c$syslog$community_id = c$community_id;
    }

@endif
