@load ./main
@load base/utils/directions-and-hosts

module Netbase;

export {

    redef record Netbase::observation += {
        ## Unique ports communicated with internally
        int_ports: set[string] &optional;                  
        ## Count of unique ports communicated with internally
        int_port_cnt: count &default=0 &log;               
        ## Unique hosts communicated with internally
        int_hosts: set[string] &optional;                  
        ## Count of unique hosts communicated with internally
        int_host_cnt: count &default=0 &log;               
        ## Unique ports communicated with externally
        ext_ports: set[string] &optional;                  
        ## Count of unique ports communicated with externally
        ext_port_cnt: count &default=0 &log;               
        ## Unique IP's communicated with externally
        ext_hosts: set[string] &optional;                  
        ## Count of unique hosts communicated with externally
        ext_host_cnt: count &default=0 &log;               
        ## Unique internal clients communicating with this IP
        int_clients: set[string] &optional;                
        ## Count of unique internal clients communicating with this IP
        int_client_cnt: count &default=0 &log;             
        ## Unique external clients communicating with this IP
        ext_clients: set[string] &optional;                
        ## Count fo unique external clients communicating with this IP
        ext_client_cnt: count &default=0 &log;             
        ## Total count of connections this IP was involved in
        total_conns: count &default=0 &log;                
        ## Total count of external conns originated by this IP
        out_orig_conns: count &default=0 &log;             
        ## Count of outbound conns originated by this IP that were successful
        out_succ_conns: count &default=0 &log;             
        ## Count of outbound conns originated by this IP that were rejected
        out_rej_conns: count &default=0 &log;              
        ## Count of outbound conns originated by this IP to ports >= 1024
        out_to_highports: count &default=0 &log;           
        ## Count of outbound conns originated by this IP to ports < 1024
        out_to_lowports: count &default=0 &log;            
        ## Count of outbound conns to a recognized service (service field populated)
        out_to_service: count &default=0 &log;             
        ## Total count of internal conns originated by this host 
        int_orig_conns: count &default=0 &log;             
        ## Count of internal conns originated by this host that were rejected
        int_rej_conns: count &default=0 &log;              
        ## Count of internal conns to ports >= 1024
        int_to_highports: count &default=0 &log;           
        ## Count of internal conns to ports < 1024     
        int_to_lowports: count &default=0 &log;            
        ## Count of internal conns to recognized server (service field populated)
        int_to_service: count &default=0 &log;             
        ## Count of internal conns this IP responded to 
        int_resp_conns: count &default=0 &log;             
        ## Sum of bytes sent as originator in internal conns
        int_orig_bytes_sent: count &default=0 &log;        
        ## Sum of bytes received as originator in internal conns 
        int_orig_bytes_rcvd: count &default=0 &log;        
        ## Sum of bytes sent as originator in external conns
        out_orig_bytes_sent: count &default=0 &log;        
        ## Sum of bytes received as originator in external conns
        out_orig_bytes_rcvd: count &default=0 &log;        
        ## Count of packets sent in internal conns 
        int_orig_pkts_sent: count &default=0 &log;         
        ## Count of packets recevied in internal conns
        int_orig_pkts_recvd: count &default=0 &log;        
        ## Count of packets sent as originator in outbound conns
        out_orig_pkts_sent: count &default=0 &log;         
        ## Count of packets received as originator in outbound conns 
        out_orig_pkts_recvd: count &default=0 &log;        
        ## Count of SMB connections as a client
        smb_client_conns: count &default=0 &log;           
        ## Count of SMB connections as a server
        smb_server_conns: count &default=0 &log;
        # Container for smb-related PCR stats           
        pcr_smb: Netbase::numstats &default=Netbase::numstats();
        ## Avg pcr for smb connections
        pcr_smb_avg: double &optional &log;
        ## Max pcr for smb connections
        pcr_smb_max: double &optional &log;
        ## Min pcr for smb connections
        pcr_smb_min: double &optional &log;
        ## Count of http connections as client 
        http_client_conns: count &default=0 &log;
        ## Count of http connections as server
        http_server_conns: count &default=0 &log;
        ## Container for http pcr stats
        pcr_http: Netbase::numstats &default=Netbase::numstats();
        ## Avg pcr for http connections
        pcr_http_avg: double &optional &log;
        ## Max pcr for http connections
        pcr_http_max: double &optional &log;
        ## Min pcr for http connections
        pcr_http_min: double &optional &log;
        ## Count of dns connections as client 
        dns_client_conns: count &default=0 &log;
        ## Count of dns connections as server 
        dns_server_conns: count &default=0 &log;
        ## Container for dns pcr stats
        pcr_dns: Netbase::numstats &default=Netbase::numstats();
        ## Avg pcr dns connections 
        pcr_dns_avg: double &optional &log;
        ## Max pcr for dns connections
        pcr_dns_max: double &optional &log;
        ## Min pcr for dns connections 
        pcr_dns_min: double &optional &log;
        ## Count of ssl connection as client 
        ssl_client_conns: count &default=0 &log;
        ## Count of ssl connections as server 
        ssl_server_conns: count &default=0 &log;
        ## Container for ssl pcr stats 
        pcr_ssl: Netbase::numstats &default=Netbase::numstats();
        ## Avg pcr for ssl connections
        pcr_ssl_avg: double &optional &log;
        ## Max pcr for ssl connections
        pcr_ssl_max: double &optional &log;
        ## Min pcr for ssl connections
        pcr_ssl_min: double &optional &log;
        ## Count of rdp connections as client 
        rdp_client_conns: count &default=0 &log;
        ## Count of rdp connections as server
        rdp_server_conns: count &default=0 &log;
        ## Container for rdp pcr stats
        pcr_rdp: Netbase::numstats &default=Netbase::numstats();
        ## Avg pcr for rdp connections
        pcr_rdp_avg: double &optional &log;
        ## Max pcr for rdp connections
        pcr_rdp_max: double &optional &log;
        ## Min pcr for rdp connections
        pcr_rdp_min: double &optional &log;
    };
}

# Function to gather flow stats for IPs in a given connection 
function Netbase::get_flow_obs(c: connection, do_orig: bool, do_resp: bool)
    {
    if ( ! do_orig && ! do_resp )
        return;

    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    local pkg = observables();

    if ( do_orig )
        {
        pkg[orig] = set([$name="total_conns"]);        
        }

    if ( do_resp )
        {
        pkg[resp] = set([$name="total_conns"]);
        }

    local rp = port_to_count(c$id$resp_p); 

    #  Internal -> external flow?
    if ( id_matches_direction(c$id, OUTBOUND) && do_orig )
        {
        add pkg[orig][[$name="ext_ports", $val=cat(c$id$resp_p)]];
        add pkg[orig][[$name="ext_hosts", $val=cat(c$id$resp_h)]];
        add pkg[orig][[$name="out_orig_conns"]];

        if ( c$orig?$size )
            add pkg[orig][[$name="out_orig_bytes_sent", $val=cat(c$orig$size)]];
            
        if ( c$resp?$size )
            add pkg[orig][[$name="out_orig_bytes_rcvd", $val=cat(c$resp$size)]];
            
        if ( c$orig?$num_pkts )
            add pkg[orig][[$name="out_orig_pkts_sent", $val=cat(c$orig$num_pkts)]];
            
        if ( c$resp?$num_pkts )
            add pkg[orig][[$name="out_orig_pkts_recvd", $val=cat(c$resp$num_pkts)]];
            
        if ( c$conn?$conn_state )
            {
            switch (c$conn$conn_state)
                {
                case "SF":
                    add pkg[orig][[$name="out_succ_conns"]];
                    break;
                case "REJ":
                    add pkg[orig][[$name="out_rej_conns"]];
                    fallthrough;                    
                }
            }

        if ( c?$service && |c$service| > 0 )
            add pkg[orig][[$name="out_to_service"]];
            
        if ( rp >= 1024)
            add pkg[orig][[$name="out_to_highports"]];
        else if ( rp < 1024 ) 
            add pkg[orig][[$name="out_to_lowports"]];
        }   
    # Internal -> internal flow?
    else if ( addr_matches_host(orig,LOCAL_HOSTS) && addr_matches_host(resp,LOCAL_HOSTS) )
        {
        if ( do_resp )
            {
            add pkg[resp][[$name="int_clients", $val=cat(orig)]];
            add pkg[resp][[$name="int_resp_conns"]];           
            }

        if ( do_orig )
            {
            add pkg[orig][[$name="int_ports", $val=cat(c$id$resp_p)]];
            add pkg[orig][[$name="int_hosts", $val=cat(resp)]];
            add pkg[orig][[$name="int_orig_conns"]];

            if ( c?$service && |c$service| > 0 )
                add pkg[orig][[$name="int_to_service"]];

            if ( c$orig?$size )
                {
                add pkg[orig][[$name="int_orig_bytes_sent", $val=cat(c$orig$size)]];
                }

            if ( c$resp?$size )
                {
                add pkg[orig][[$name="int_orig_bytes_rcvd", $val=cat(c$resp$size)]];
                }

            if ( c$orig?$num_pkts )
                {
                add pkg[orig][[$name="int_orig_pkts_sent", $val=cat(c$orig$num_pkts)]];
                }

            if ( c$resp?$num_pkts )
                {
                add pkg[orig][[$name="int_orig_pkts_recvd", $val=cat(c$resp$num_pkts)]];
                }

            if ( c$conn?$conn_state )
                {
                switch (c$conn$conn_state)
                    {
                    case "SF":
                        add pkg[orig][[$name="int_conns"]];
                        break;
                    case "REJ":
                        add pkg[orig][[$name="int_rej_conns"]];
                        fallthrough;
                    }
                }
             
            if ( rp >= 1024)
                {
                add pkg[orig][[$name="int_to_highports"]];
                }
            else if ( rp < 1024 ) 
                {
                add pkg[orig][[$name="int_to_lowports"]];
                }
            }
        }
    # External -> internal flow?
    else if ( id_matches_direction(c$id, INBOUND) && do_resp )
        {
        add pkg[resp][[$name="server_conns"]];
        add pkg[resp][[$name="ext_clients", $val=cat(orig)]];
        }

    # Now check the service field
    for ( s in c$service )
        {
        switch s 
            {
            case "DNS":
                # found dns
                if ( do_orig ) 
                    {
                    add pkg[orig][[$name="dns_client_conns"]];
                    if ( c$conn?$pcr )
                        add pkg[orig][[$name="pcr_dns", $val=cat(c$conn$pcr)]];
                    }
                if ( do_resp )
                    {
                    add pkg[resp][[$name="dns_server_conns"]];
                    }
                break;

            case "SSL":
                if ( do_orig ) 
                    {
                    add pkg[orig][[$name="ssl_client_conns"]];
                    if ( c$conn?$pcr )
                        add pkg[orig][[$name="pcr_ssl", $val=cat(c$conn$pcr)]];
                    }
                if ( do_resp )
                    {
                    add pkg[resp][[$name="ssl_server_conns"]];
                    }
                break;

            case "RDP":
                if ( do_orig ) 
                    {
                    add pkg[orig][[$name="rdp_client_conns"]];
                    if ( c$conn?$pcr )
                        add pkg[orig][[$name="pcr_rdp", $val=cat(c$conn$pcr)]];
                    }
                if ( do_resp )
                    {
                    add pkg[resp][[$name="rdp_server_conns"]];
                    }
                break;

            case "SMB":
                if ( do_orig ) 
                    {
                    add pkg[orig][[$name="smb_client_conns"]];
                    if ( c$conn?$pcr )
                        add pkg[orig][[$name="pcr_smb", $val=cat(c$conn$pcr)]];
                    }
                if ( do_resp )
                    {
                    add pkg[resp][[$name="smb_server_conns"]];
                    }
                break;

            case "HTTP":
                if ( do_orig ) 
                    {
                    add pkg[orig][[$name="http_client_conns"]];
                    if ( c$conn?$pcr )
                        add pkg[orig][[$name="pcr_http", $val=cat(c$conn$pcr)]];
                    }
                if ( do_resp )
                    {
                    add pkg[resp][[$name="http_server_conns"]];
                    }
                break;
            }
        } 

    # See if the observable pkgs need delivering
    if ( do_orig )
        {
        Netbase::SEND(orig, pkg[orig]);
        }

    if ( do_resp )
        {
        Netbase::SEND(resp, pkg[resp]);
        }
    }

# Handler for grabbing unique value counts for logging
event Netbase::log_observation(obs: observation)
    {
    obs$int_port_cnt = |obs$int_ports|;
    obs$int_host_cnt = |obs$int_hosts|;
    obs$ext_port_cnt = |obs$ext_ports|; 
    obs$ext_host_cnt = |obs$ext_hosts|;

    obs$int_client_cnt = |obs$int_clients|;
    obs$ext_client_cnt = |obs$ext_clients|;

    if ( obs$pcr_dns$cnt > 0 ) 
        {
        obs$pcr_dns_avg = obs$pcr_dns$avg;
        obs$pcr_dns_max = obs$pcr_dns$max;
        obs$pcr_dns_min = obs$pcr_dns$min;
        }

    if ( obs$pcr_http$cnt > 0 ) 
        {
        obs$pcr_http_avg = obs$pcr_http$avg;
        obs$pcr_http_max = obs$pcr_http$max;
        obs$pcr_http_min = obs$pcr_http$min;
        }

    if ( obs$pcr_ssl$cnt > 0 ) 
        {
        obs$pcr_ssl_avg = obs$pcr_ssl$avg;
        obs$pcr_ssl_max = obs$pcr_ssl$max;
        obs$pcr_ssl_min = obs$pcr_ssl$min;
        }

    if ( obs$pcr_smb$cnt > 0 ) 
        {
        obs$pcr_smb_avg = obs$pcr_smb$avg;
        obs$pcr_smb_max = obs$pcr_smb$max;
        obs$pcr_smb_min = obs$pcr_smb$min;
        }

    if ( obs$pcr_rdp$cnt > 0 ) 
        {
        obs$pcr_rdp_avg = obs$pcr_rdp$avg;
        obs$pcr_rdp_max = obs$pcr_rdp$max;
        obs$pcr_rdp_min = obs$pcr_rdp$min;
        }
    }

# Hook handler to initialize sets 
hook Netbase::customize_obs(ip: addr, obs: table[addr] of observation)
     {           
     obs[ip]$int_ports=set();
     obs[ip]$int_hosts=set();
     obs[ip]$ext_ports=set();
     obs[ip]$ext_hosts=set();
     obs[ip]$int_clients=set();
     obs[ip]$ext_clients=set();
     }

# Handler to load observables into the observations table
# This event is executed every time a node calls the SEND()
# function.  
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
event Netbase::add_observables(ip: addr, obs: set[observable])
    {
    for ( o in obs )
        {
        switch o$name
            {
            case "int_ports":
                add observations[ip]$int_ports[o$val];
                break;
            case "int_hosts":
                add observations[ip]$int_hosts[o$val];
                break;
            case "ext_ports":
                add observations[ip]$ext_ports[o$val];
                break;
            case "ext_hosts":
                add observations[ip]$ext_hosts[o$val];
                break;
            case "int_clients":
                add observations[ip]$int_clients[o$val];
                break;
            case "ext_clients":
                add observations[ip]$ext_clients[o$val];
                break;
            case "total_conns":
                ++observations[ip]$total_conns;
                break;
            case "out_succ_conns":
                ++observations[ip]$out_succ_conns;
                break;
            case "out_rej_conns":
                ++observations[ip]$out_rej_conns;
                break;
            case "out_to_highports":
                ++observations[ip]$out_to_highports;
                break;
            case "out_to_lowports":
                ++observations[ip]$out_to_lowports;
                break;
            case "out_to_service":
                ++observations[ip]$out_to_service;
                break;
            case "int_orig_conns":
                ++observations[ip]$int_orig_conns;
                break;
            case "int_rej_conns":
                ++observations[ip]$int_rej_conns;
                break;
            case "int_to_highports":
                ++observations[ip]$int_to_highports;
                break;
            case "int_to_lowports":
                ++observations[ip]$int_to_lowports;
                break;
            case "int_to_service":
                ++observations[ip]$int_to_service;
                break;
            case "int_resp_conns":
                ++observations[ip]$int_resp_conns;
                break;
            case "int_orig_bytes_sent":
                observations[ip]$int_orig_bytes_sent = observations[ip]$int_orig_bytes_sent + to_count(o$val);
                break;
            case "int_orig_bytes_rcvd":
                observations[ip]$int_orig_bytes_rcvd = observations[ip]$int_orig_bytes_rcvd + to_count(o$val);
                break;
            case "out_orig_bytes_sent":
                observations[ip]$out_orig_bytes_sent = observations[ip]$out_orig_bytes_sent + to_count(o$val);
                break;
            case "out_orig_bytes_rcvd":
                observations[ip]$out_orig_bytes_rcvd = observations[ip]$out_orig_bytes_rcvd + to_count(o$val);
                break;
            case "int_orig_pkts_sent":
                observations[ip]$int_orig_pkts_sent = observations[ip]$int_orig_pkts_sent + to_count(o$val);
                break;
            case "int_orig_pkts_recvd":
                observations[ip]$int_orig_pkts_recvd = observations[ip]$int_orig_pkts_recvd + to_count(o$val);
                break;
            case "out_orig_pkts_sent":
                observations[ip]$out_orig_pkts_sent = observations[ip]$out_orig_pkts_sent + to_count(o$val);
                break;
            case "out_orig_pkts_recvd":
                observations[ip]$out_orig_pkts_recvd = observations[ip]$out_orig_pkts_recvd + to_count(o$val);
                break;
            case "pcr_dns":
                observations[ip]$pcr_dns = Netbase::update_numstats(observations[ip]$pcr_dns, to_double(o$val));
                break;
            case "pcr_ssl":
                observations[ip]$pcr_ssl = Netbase::update_numstats(observations[ip]$pcr_ssl, to_double(o$val));
                break;
            case "pcr_http":
                observations[ip]$pcr_http = Netbase::update_numstats(observations[ip]$pcr_http, to_double(o$val));
                break;
            case "pcr_smb":
                observations[ip]$pcr_smb = Netbase::update_numstats(observations[ip]$pcr_smb, to_double(o$val));
                break;
            case "pcr_rdp":
                observations[ip]$pcr_rdp = Netbase::update_numstats(observations[ip]$pcr_rdp, to_double(o$val));
                break;     
            case "dns_server_conns":
                ++observations[ip]$dns_server_conns;
                break;       
            case "dns_client_conns":
                ++observations[ip]$dns_client_conns;
                break;       
            case "http_server_conns":
                ++observations[ip]$http_server_conns;
                break;       
            case "http_client_conns":
                ++observations[ip]$http_client_conns;
                break;   
            case "ssl_server_conns":
                ++observations[ip]$ssl_server_conns;
                break;       
            case "ssl_client_conns":
                ++observations[ip]$ssl_client_conns;
                break;      
            case "smb_server_conns":
                ++observations[ip]$smb_server_conns;
                break;       
            case "smb_client_conns":
                ++observations[ip]$smb_client_conns;
                break;      
            case "rdp_server_conns":
                ++observations[ip]$rdp_server_conns;
                break;       
            case "rdp_client_conns":
                ++observations[ip]$rdp_client_conns;
                break;             
            }       
        }
    }
@endif

# Hanndler to vet the connection and start observations
event connection_state_remove(c: connection)
    {
    if ( ! c?$id )
        return;
    
    Netbase::get_flow_obs(c, Netbase::is_monitored(c$id$orig_h), Netbase::is_monitored(c$id$resp_h));
    }







