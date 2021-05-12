@ifdef (SMB::TreeInfo)
export {
    redef record SMB::TreeInfo += {
        community_id: string &optional &log;
    };
}
@endif

@ifdef (SMB::FileInfo)
export{
    redef record SMB::FileInfo += {
        community_id: string &optional &log;
    };
}
@endif 


@ifdef (SMB::CmdInfo)
export {
    redef record SMB::CmdInfo += {
        community_id: string &optional &log;
    };
}
@endif

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=-10
    {
    @ifdef (SMB::CmdInfo)
    if ( c$smb_state?$current_cmd && ! c$smb_state$current_cmd?$community_id && c?$community_id )
        c$smb_state$current_cmd$community_id = c$community_id;
    @endif

    @ifdef (SMB::FileInfo)
    if ( c$smb_state?$current_file && ! c$smb_state$current_file?$community_id && c?$community_id )
        c$smb_state$current_file$community_id = c$community_id;
    @endif

    @ifdef (SMB::TreeInfo)
    if ( c$smb_state?$current_tree && ! c$smb_state$current_tree?$community_id && c?$community_id )
        c$smb_state$current_tree$community_id = c$community_id;
    @endif
    }

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=-10
    {
    @ifdef (SMB::CmdInfo)
    if ( c$smb_state?$current_cmd && ! c$smb_state$current_cmd?$community_id && c?$community_id )
        c$smb_state$current_cmd$community_id = c$community_id;
    @endif

    @ifdef (SMB::FileInfo)
    if ( c$smb_state?$current_file && ! c$smb_state$current_file?$community_id && c?$community_id )
        c$smb_state$current_file$community_id = c$community_id;
    @endif

    @ifdef (SMB::TreeInfo)
    if ( c$smb_state?$current_tree && ! c$smb_state$current_tree?$community_id && c?$community_id )
        c$smb_state$current_tree$community_id = c$community_id;
    @endif
    }
