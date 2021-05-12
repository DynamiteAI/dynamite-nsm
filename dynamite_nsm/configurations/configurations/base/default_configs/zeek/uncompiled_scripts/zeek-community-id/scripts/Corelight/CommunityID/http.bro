@ifdef (HTTP::Info)

export {
# Add the ID to the http record 
    redef record HTTP::Info += {
        community_id: string &optional &log;
    };
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if (! c$http?$community_id && c?$community_id)
        c$http$community_id = c$community_id;
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    if (! c$http?$community_id && c?$community_id)
        c$http$community_id = c$community_id;
    }

@endif