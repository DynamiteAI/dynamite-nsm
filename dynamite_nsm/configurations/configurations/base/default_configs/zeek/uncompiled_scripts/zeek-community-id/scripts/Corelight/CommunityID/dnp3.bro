@ifdef (DNP3::Info)

export {
    redef record DNP3::Info += {
        community_id: string &optional &log;
    };
}

event dnp3_application_request_header(c: connection, is_orig: bool, application: count, fc: count)
    {
    if ( ! c$dnp3?$community_id && c?$community_id )
        c$dnp3$community_id = c$community_id;
    }

event dnp3_application_response_header(c: connection, is_orig: bool, application: count, fc: count, iin: count)
    {
    if ( ! c$dnp3?$community_id && c?$community_id )
        c$dnp3$community_id = c$community_id;
    }

@endif