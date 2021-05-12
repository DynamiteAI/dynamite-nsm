@ifdef (NTP::Info)
export {
    redef record NTP::Info += {
        community_id: string &optional &log;
    };
}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message)
    {
    if ( ! c$ntp?$community_id && c?$community_id )
        c$ntp$community_id = c$community_id; 
    }
@endif