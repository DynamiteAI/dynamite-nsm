@ifdef (DCE_RPC::Info)
export {
    redef record DCE_RPC::Info += {
        community_id: string &optional &log;
    };
}

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
    {
    if ( ! c$dce_rpc?$community_id && c?$community_id )
        c$dce_rpc$community_id = c$community_id;
    }

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
    {
    if ( ! c$dce_rpc?$community_id && c?$community_id )
        c$dce_rpc$community_id = c$community_id;
    }

@endif