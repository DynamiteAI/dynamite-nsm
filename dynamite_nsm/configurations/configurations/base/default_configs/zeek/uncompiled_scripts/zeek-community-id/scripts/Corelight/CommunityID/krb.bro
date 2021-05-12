@ifdef (KRB::Info)

export {
    redef record KRB::Info += {
        community_id: string &optional &log;
    };
}

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
    {
    if ( ! c$krb?$community_id && c?$community_id )
        c$krb$community_id = c$community_id;  
    }

event krb_ap_response(c: connection)
    {
    if ( ! c$krb?$community_id && c?$community_id )
        c$krb$community_id = c$community_id;
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    if ( ! c$krb?$community_id && c?$community_id )
        c$krb$community_id = c$community_id;
    }

event krb_as_response(c: connection, msg: KRB::KDC_Response)
    {
    if ( ! c$krb?$community_id && c?$community_id )
        c$krb$community_id = c$community_id;
    }

event krb_tgs_request(c: connection, msg: KRB::KDC_Request)
    {
    if ( ! c$krb?$community_id && c?$community_id )
        c$krb$community_id = c$community_id;
    }

event krb_tgs_response(c: connection, msg: KRB::KDC_Response)
    {
    if ( ! c$krb?$community_id && c?$community_id )
        c$krb$community_id = c$community_id;
    }
    
@endif
