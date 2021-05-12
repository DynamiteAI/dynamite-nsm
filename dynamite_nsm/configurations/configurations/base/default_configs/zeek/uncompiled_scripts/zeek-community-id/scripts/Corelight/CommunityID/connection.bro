#! Module to set up community_id and add it to the connection
#! record when a new connection is created. 

module CommunityID;

export {
    # An unsigned 16-bit number to seed our hashing
    const seed: count = 0 &redef;

    # Whether to add a base64 pass over the hash digest.
    # Enabled by default, since it shortens the output.
    const do_base64: bool = T &redef;

    # Verbose debugging log output to the console.
    const verbose: bool = F &redef;

    # Add the ID string field to the connection record, for reuse
    # during its lifespan
    redef record connection += {
        community_id: string &optional;
    };

    # Add the ID to the conn record 
    redef record Conn::Info += {
        community_id: string &optional &log;
    };
}

# Add the community_id to each newly tracked connection
event new_connection(c: connection) &priority=-10
    {
    c$community_id = hash_conn(c);
    }

# Add the ID to the conn log
event connection_state_remove(c: connection) 
    {
    if (c?$community_id) 
        c$conn$community_id = c$community_id;
    }
