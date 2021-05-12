@ifdef (SSH::Info)
export {
    redef record SSH::Info += {
        community_id: string &optional &log;
    };
}

event ssh_client_version(c: connection, version: string)
    {
    if ( ! c$ssh?$community_id && c?$community_id )
        c$ssh$community_id = c$community_id;
    }

event ssh_server_version(c: connection, version: string)
    {
    if ( ! c$ssh?$community_id && c?$community_id )
        c$ssh$community_id = c$community_id;
    }

@endif