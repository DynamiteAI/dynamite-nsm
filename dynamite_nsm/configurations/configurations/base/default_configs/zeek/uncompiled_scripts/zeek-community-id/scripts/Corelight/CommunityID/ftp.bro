@ifdef (FTP::Info)

export {
    redef record FTP::Info += {
        community_id: string &optional &log;
    };
}

event ftp_request(c: connection, command: string, arg: string)
    {
    if ( ! c$ftp?$community_id && c?$community_id )
        c$ftp$community_id = c$community_id;
    }

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
    {
    if ( ! c$ftp?$community_id && c?$community_id )
        c$ftp$community_id = c$community_id;
    }

@endif