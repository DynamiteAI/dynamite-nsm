#! This script defines the core components of Netbase.  

@load base/utils/directions-and-hosts 
# @load user_custom/flow_labels   # Add me later... 

# Define module namespace
module Netbase;

# Declare exports 
export {
    ## The netbase log stream identifier. 
    redef enum Log::ID += { LOG };
    
    ## Add PCR to the conn log (Conn::Info record)
    redef record Conn::Info += {
        pcr: double &log &optional;
    };

    ## The record type that defines the fields in the log stream as well 
    ## the observables that are being tracked for each monitored host. 
    type observation: record {
        address: addr &log &optional;
        starttime: time &log &optional;
        endtime: time &log &optional;
    } &redef;

    ## Amount of time observations are tracked before being written to the log 
    const obs_interval: interval = 5 mins &redef;

    ## Function called when an entry expires from the observations table. 
    ## It converts unique lists to counts, prepares the entry for logging
    ## and sends it on to the logging framework.  
    global close_obs: function(data: table[addr] of observation, idx: addr): interval;

    ## Table for housing running observations for monitored IP addresses.  The observations
    ## table is distributed across proxy nodes in the cluster using the data partitioing API. 
    ## Arbitrary time buckets are created using the &create_expire attribute, when a key 
    ## expires from the table the close_obs function is executed to prepare the record for logging. 
    global observations: table[addr] of observation = table() &create_expire=obs_interval &expire_func=close_obs;  # <-- CHANGE ME

    ## Event executed when preparing an observation for logging. 
    global log_observation: event(p: Netbase::observation);

    ## Event executed when an observation is written to the log, e.g. 
    ## by calling the Log::write function.  
    global write_obs_log: event(p: Netbase::observation);

    ## Type for sharing observed attributes and behaviors (observables)
    ## with the aggregation nodes, typcially proxies in a cluster. 
    type observable: record { 
        ## The name of the observable. This is a unique descriptor that 
        ## should match any fields added to the observations record.  The 
        ## observable name is what is used to bind the script logic that makes
        ## the observation with the name of the behavior or attribute that is 
        ## being tracked by netbase.  Everything is in the name, so take care 
        ## to make sure names are concise, easy to understand and follow a 
        ## consistent convention that makes ingest and analysis easier downstream. 
        name: string;
        ## The optional value of the observable.  Optional because not every 
        ## observable is meant to track unique instances of a data point as it relates
        ## to monitored IP addresses.  Use the val field to supply unique instances of 
        ## a thing along with the name of the observable.  Values should be cast as a 
        ## string type for transport and can be later converted back to their original 
        ## type as needed. 
        val: string &optional;
    };
    
    ## Record for calculating and storing number stats
    type numstats: record {
        cnt: count &default=0;
        min: double &optional;
        max: double &optional;
        sum: double &optional;
        avg: double &optional;
    };

    ## Function for updating an numstats record based on the provided value 
    global update_numstats: function(rec: numstats, val: double): numstats;

    ## Function for publishing observables to the proxy pool. Used in Netbase modules
    ## to ensure consistent hanlding of observables. 
    global SEND: function(ip: addr, obs: set[observable]);

    ## Reusable table type for temporary storage of observables within event handlers.
    ## The observables table is typically instantiaded as a local variable, then used 
    ## to accumulate all observables for monitored IP's, for a given event.  Once the 
    ## event handler completes, the keys in the table (IP's) and values (set of observables) 
    ## are passed to the SEND function for publishing to the proxy pool. 
    ##
    ## The intent is to minimize overlapping/redundant transmissions of observables
    ## related to a given connection, reducing strain on the Broker comms
    ## and processing load on proxies.  
    type observables: table[addr] of set[observable];

    ## Hook used by netbase modules to customize fields in the observation entry after 
    ## it has been added to the observations table.  This hook is not frequently needed
    ## as observation record fields can be declared with a default initialization value
    ## (e.g. an empty set). 
    global customize_obs: hook(ip: addr, observations: table[addr] of observation);

    ## Event used by publish_hrw to invoke handling on the receiving node. 
    global add_observables: event(ip: addr, pkg: set[observable]);

    ## Patern describing IP addresses that should never be monitored; e.g. broadcast 
    ## and multicast addresses that might fall within monitored networks. 
    # const excluded_hosts: pattern = /^255\.|\.255$|^2[23][0-9]\.|/;

    ## List of subnets that contain critical assets.  Hosts or subnets defined in the list
    ## will be monitored in addition to those that match the monitoring mode. 
    ## Values are of type subnet but individual IP addresses can be 
    ## defined using a /32 mask: ex. 192.168.10.1/32   
    global critical_assets: set[subnet] &default=set() &redef;

    ## Enum that defines the available monitoring modes.  Observations will be made and 
    ## logged for IP's that match this type.
    type mode: enum {
        ## Make observations for any IP within a non-routable RFC 1918 address range. 
        PRIVATE_NETS,
        ## Make observations for any IP within a Site::local_nets subnet. 
        LOCAL_NETS,
        ## Make observations for any IP within a Site:local_nets or Site::local_neighbors subnets.  
        LOCAL_AND_NEIGHBORS
    };

    ## The monitoring mode Netbase is using to make and log observations.  Refer to Netbase::mode
    ## for more information. 
    const monitoring_mode: Netbase::mode = LOCAL_NETS &redef;

    ## Function to determine if observations should be made for the given IP address. 
    global is_monitored: function(ip: addr): bool;

    ## Function to calculate PCR using the provided counts which are presumably 
    ## originator bytes (o) and responder bytes (r)
    global calc_pcr: function(o: count, r: count): double;
}

function SEND(ip: addr, obs: set[observable])
    {
    Cluster::publish_hrw(Cluster::proxy_pool, ip, add_observables, ip, obs);
    event Netbase::add_observables(ip, obs);         
    }

# Event called when its time to write an observation to the log stream. 
# Any handlers that need to modify the record before it is logged, should set a higher 
# priority level 
event log_observation(obs: observation) &priority=-10
    {
    # Write the IP observation log entry. Only proxies do this in a cluster   
    @if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
        Log::write(Netbase::LOG, obs);
    @endif
    }

## Function to determine if observations should be made for a given IP
function is_monitored(ip: addr): bool
    {
    if (/^255\.|\.255$/ in cat(ip) )
        return F;

    switch monitoring_mode {
        case PRIVATE_NETS:
            if ( ip in Site::private_address_space )
                return T;
            break;
        case LOCAL_NETS:
            if ( ip in Site::local_nets)
                return T;
            break;
        case LOCAL_AND_NEIGHBORS:
            if ( ip in Site::local_nets || ip in  Site::neighbor_nets )
                return T;
            break;
    }

    # Now check if its a critical asset  
    if ( ip in critical_assets )
        return T;
    
    return F;
    }

# Update stats for a given number value
function update_numstats(rec: numstats, value: double): numstats
    {
    # increment the sample count
    rec$cnt += 1;

    if ( rec?$sum )
        rec$sum += value;
    else
        rec$sum = value;
    
    # update the running average
    rec$avg = rec$sum / rec$cnt;

    # check if new min
    if ( rec?$min )
        {
        if (value < rec$min)
            {
            rec$min = value;
            }    
        }
    else
        rec$min = value;
    
    # or if new max
    if ( rec?$max )
        {
        if (value > rec$max)
            {
            rec$max = value;
            }
        }
    else 
        rec$max = value;

    return rec;
    }

# Function to handle expiring observations
function close_obs(data: table[addr] of observation, idx: addr): interval 
    {
    # Set the endtime 
    data[idx]$endtime = network_time();

    # Event for handling by other scripts to update fields 
    # before the observation is logged 
    event Netbase::log_observation(data[idx]);

    # Expire the entry now
    return 0 secs;
    }

# Function to calculate PCR given two numbers (presumably byte counts)
# we're not doing any safety checks so caller must ensure valid 
# args are supplied. 
function calc_pcr(o: count, r: count): double
    {
    local n = (o + 0.0) - (r + 0.0);
    local d = (o + 0.0) + (r + 0.0);

    return ( n / d );
    }

# Add pcr to all connections where data was exchanged 
event connection_state_remove (c: connection) &priority=3 
    {
    
    if ( ! c$orig?$size || ! c$resp?$size ) {
        return;
    }
    else if (c$orig$size == 0 && c$resp$size == 0 ) {
        return;   
    }
    else {
        c$conn$pcr = calc_pcr(c$orig$size, c$resp$size);
    }
}

# Drop local suppression cache on workers to force HRW key repartitioning.
#   Taking the lead from known_hosts here...  
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::WORKER ) 
event Cluster::node_up(name: string, id: string)
    {
    Netbase::observations = table();
    }
@endif

# Drop local suppression cache on workers to force HRW key repartitioning.
#   Taking the lead from known_hosts here again...  
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::WORKER ) 
event Cluster::node_down(name: string, id: string)
    {
    Netbase::observations = table();
    }
@endif

# Function to start observing for the provided IP. 
function start_obs(ip: addr) 
    {
    if ( Netbase::is_monitored(ip) )
        {
        observations[ip] = [$address=ip,$starttime=network_time()];

        # Hook for allowing other scripts to modify the observation 
        # table. Mainly so scripts can initialize any 
        # set fields they are using 
        hook Netbase::customize_obs(ip, observations);
        }
    }

# High priority handler to ensure the IP observation record exists in the table before 
# any new values are stored. 
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY ) 
event Netbase::add_observables(ip: addr, obs: set[observable]) &priority=100
    {
    if ( ip !in observations ) 
        {
        Netbase::start_obs(ip);
        }  
    }
@endif

# Create the log stream 
event bro_init()
    {
    Log::create_stream(Netbase::LOG, [$columns=observation, $ev=Netbase::write_obs_log, $path="netbase"]);
    }