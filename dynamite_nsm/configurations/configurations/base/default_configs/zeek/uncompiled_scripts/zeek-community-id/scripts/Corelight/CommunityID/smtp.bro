@ifdef (SMTP::Info)

export {
    redef record SMTP::Info += {
        community_id: string &optional &log;
    };
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
    {
    if ( ! c$smtp?$community_id && c?$community_id )
        c$smtp$community_id = c$community_id;
    }

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
    {
    if ( ! c$smtp?$community_id && c?$community_id )
        c$smtp$community_id = c$community_id;
    }
@endif 
