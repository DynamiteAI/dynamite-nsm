@ifdef (RFB::Info)
export {
    redef record RFB::Info += {
        community_id: string &optional &log;
    };
}

event rfb_client_version(c: connection, major_version: string, minor_version: string)
    {
    if ( ! c$rfb?$community_id && c?$community_id )
        c$rfb$community_id = c$community_id;
    }

event rfb_server_version(c: connection, major_version: string, minor_version: string)
    {
    if ( ! c$rfb?$community_id && c?$community_id )
        c$rfb$community_id = c$community_id;
    }

@endif 