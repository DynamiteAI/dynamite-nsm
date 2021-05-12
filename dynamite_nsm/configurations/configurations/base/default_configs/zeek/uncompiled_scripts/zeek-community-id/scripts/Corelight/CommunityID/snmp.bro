@ifdef (SNMP::Info)
export {
    redef record SNMP::Info += {
        community_id: string &optional &log;
    };
}

event snmp_get_request(c: connection , is_orig: bool , header: SNMP::Header , pdu: SNMP::PDU)
    {
    if ( ! c$snmp?$community_id && c?$community_id )
        c$snmp$community_id = c$community_id;
    }

event snmp_set_request(c: connection , is_orig: bool , header: SNMP::Header , pdu: SNMP::PDU)
    {
    if ( ! c$snmp?$community_id && c?$community_id )
        c$snmp$community_id = c$community_id;
    }

event snmp_response(c: connection , is_orig: bool , header: SNMP::Header , pdu: SNMP::PDU)
    {
    if ( ! c$snmp?$community_id && c?$community_id )
        c$snmp$community_id = c$community_id;
    }
@endif