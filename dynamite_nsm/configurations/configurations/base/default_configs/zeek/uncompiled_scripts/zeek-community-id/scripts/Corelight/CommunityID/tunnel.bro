### No suitable events for accessing connection and Tunnel::Info records

@ifdef (Tunnel::Info)
export {
    redef record Tunnel::Info += {
        community_id: string &optional &log;
    };
}
@endif
