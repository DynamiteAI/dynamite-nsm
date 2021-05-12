@ifdef (Modbus::Info)
export {
    redef record Modbus::Info += {
        community_id: string &optional &log;
    };
}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
    {
    if ( ! c$modbus?$community_id && c?$community_id )
        c$modbus$community_id = c$community_id;
    }
@endif