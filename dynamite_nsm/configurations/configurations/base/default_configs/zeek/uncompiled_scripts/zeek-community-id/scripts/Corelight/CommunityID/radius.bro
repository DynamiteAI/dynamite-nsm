@ifdef (RADIUS::Info)

export {
    redef record RADIUS::Info += {
        community_id: string &optional &log;
    };
}

event radius_message(c: connection, result: RADIUS::Message)
    {
    if ( ! c$radius?$community_id && c?$community_id )
        c$radius$community_id = c$community_id;
    }

@endif