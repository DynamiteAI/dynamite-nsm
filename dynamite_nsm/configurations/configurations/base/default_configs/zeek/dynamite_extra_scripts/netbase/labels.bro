@load ./main
@load base/frameworks/cluster


export {

	redef Netbase::observation += {
	    # Label fields
        ## Static and dynamic labels associated with the device
	    ip_labels: set[string] &optional &log;
        ## Static and dynmaic labels associated with conns the device was involved in
	    flow_labels: set[string] &optional &log;
	};

    ## Holds the set of all known hosts.  Keys in the store are addresses
    ## and their associated value will always be the "true" boolean.
    global Netbase::labels: Cluster::StoreInfo;

    ## Record for 
    type conn_labels: record {
        orig: set[string] &optional &log;
        resp: set[string] &optional &log;
        flow: set[string] &optional &log;
    };

    ## 
    redef record Conn::Info += {
        labels: conn_labels &log &optional;
    };

    ## The Broker topic name to use for the Netbase::labels data store 
    const ip_labels_ds_name = "zeek/netbase/labels" &redef;
}

## Create the IP labels data store
event bro_init()
    {
    Netbase::labels = Cluster::create_store(Known::ip_labels_ds_name);
    }

# Function to retrieve labels from the data store
function get_labels(ip: addr)
    {
    when ( local res = Broker::get(Netbase::labels, ip) )
        {
        if ( res as set[string] )
        }
    # All data store queries must specify a timeout
    timeout 3sec
        { print "timeout", key; }
    }


# Function to gather labels 
function get_labels(c: connection)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    if ( c?$labels )
        {
        if ( orig in profiles && c$labels?$orig && |c$labels$orig| > 0 )
            {
            for ( ol in c$labels$orig )
                {
                add profiles[orig]$ip_labels[ol];   
                }
            
            if ( c$labels?$flow && |c$labels$flow| > 0 )
                {
                for ( ofl in c$labels$flow )
                    {
                    add profiles[orig]$flow_labels[ofl];
                    }                   
                }
            }
        
        if ( resp in profiles && c$labels?$resp && |c$labels$resp| > 0 )
            {
            for ( rl in c$labels$resp )
                {
                add profiles[resp]$ip_labels[rl];
                }           
        
            if ( c$labels?$flow && |c$labels$flow| > 0 )
                {
                for ( rfl in c$labels$flow )
                    {
                    add profiles[resp]$flow_labels[rfl];
                    }
                }
            }           
        }
    }

#  Initialize label containers for each connection.  
event new_connection(c: connection)
    {
    c$labels = conn_fields();
    c$labels$orig = set();
    c$labels$resp = set();
    c$labels$flow = set();
    }

event flow_labeled(c: connection)
    {
    #  Do nothing if we are missing conn Info record or needed site fields
    if ( ! c?$conn || (! c$conn?$local_orig || ! c$conn?$local_resp ))
        {
        return;
        }
    
    # Make sure we have profiles for these IPs
    get_labels(c);
    }


event bro_init() {
    if ( static_cidr_labels != "" ) {
        Input::add_event([$source=static_cidr_labels,
                          $reader=Input::READER_ASCII,
                          $mode=Input::REREAD,
                          $name="cidr_labels",
                          $fields=flow_labels::cidr_label_entry,
                          $ev=flow_labels::read_cidr_labels]);
    }
