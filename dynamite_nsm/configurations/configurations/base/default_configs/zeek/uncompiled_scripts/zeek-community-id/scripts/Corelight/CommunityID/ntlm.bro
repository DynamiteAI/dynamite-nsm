@ifdef (NTLM::Info)
export {
    redef record NTLM::Info += {
        community_id: string &optional &log;
    };
}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
    {
    if ( ! c$ntlm?$community_id && c?$community_id )
        c$ntlm$community_id = c$community_id;
    }

event ntlm_challenge(c: connection, challenge: NTLM::Challenge)
    {
    if ( ! c$ntlm?$community_id && c?$community_id )
        c$ntlm$community_id = c$community_id;
    }

event ntlm_challenge(c: connection, challenge: NTLM::Challenge)
    {
    if ( ! c$ntlm?$community_id && c?$community_id )
        c$ntlm$community_id = c$community_id;
    }

event ntlm_challenge(c: connection, challenge: NTLM::Challenge)
    {
    if ( ! c$ntlm?$community_id && c?$community_id )
        c$ntlm$community_id = c$community_id;
    }

event ntlm_negotiate(c: connection, negotiate: NTLM::Negotiate)
    {
    if ( ! c$ntlm?$community_id && c?$community_id )
        c$ntlm$community_id = c$community_id;
    }
@endif