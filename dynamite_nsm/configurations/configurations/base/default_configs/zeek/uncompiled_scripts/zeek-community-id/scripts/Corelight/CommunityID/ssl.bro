@ifdef (SSL::Info)
export {
    redef record SSL::Info += {
        community_id: string &optional &log;
    };
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
    {
    if ( c?$community_id )
        c$ssl$community_id = c$community_id;
    }

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
    {
    if ( ! c$ssl?$community_id && c?$community_id )
        c$ssl$community_id = c$community_id;    
    }

@endif