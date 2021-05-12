@load base/utils/site
@load base/protocols/dns

module DNS;

export {

    # Container for domain parts
    type domain_labels: record {
        cnt:    count   &optional;
        tld:    string  &optional;
        subs:   string &optional;
        sub1:   string    &optional;
        sub2:   string   &optional;
        sub3:   string    &optional;
        first:  string   &optional;
    };

    type labels: record {
        cnt: count &optional &log;
        tld: string &optional &log;
        lvl2: string &optional &log;
        subs: string &optional &log;
        lowest: string &optional &log;
    };

    redef record DNS::Info += {
        labels: labels &log &optional;
    };

    global get_labels: function(q: string): domain_labels;
}

function query_test(req: DNS::Info): bool
    {
    # Gotta have a query 
    if ( ! req?$query )
        return F; 

    # Skip anything on a NETBIOS port
    if (req$id$resp_p == 137/tcp || req$id$resp_p == 137/udp)
        {
        return F;
        }

    # Only do this for notable types, currently: A, AAAA, MX, CNAME, and TXT
    local notable_types: set[count] = {1, 15, 28, 5, 16};
    if (( ! req?$qtype ) || ( req$qtype !in notable_types ))
        {
        return F;
        }

    # Make sure the queried domain is not local DNS namespace
    if ( Site::is_local_name(req$query) )
        {
        return F;
        }

    # If we got this far its a notable domain
    return T;
}

function get_subs(v: vector of string): string 
    {
    local cnt = |v|;
    local stop = cnt - 2;
	local idx = 0;
	local subs = vector();
	
	while ( idx != stop ) 
		{
		subs += v[idx];
		idx += 1;
		}
	
	return join_string_vec(subs, ".");	
    }

# Extract the different domain parts
function get_labels(q: string): domain_labels
    {
    local a = domain_labels();
    local parts = split_string(q, /\./);

    a$cnt = |parts|;

    if ( a$cnt > 1 )
        {
        a$tld = parts[a$cnt - 1];
        a$sub1 = join_string_vec(vector(parts[a$cnt - 2], a$tld), ".");
        a$first = parts[0];
        if ( a$cnt >= 4)
            {
            a$sub2 = join_string_vec(vector(parts[a$cnt - 3], a$sub1), ".");
            a$sub3 = join_string_vec(vector(parts[a$cnt - 4], a$sub2), ".");
             
            a$subs = get_subs(parts);
            }
        else if ( a$cnt == 3 )
            {
            a$sub2 = join_string_vec(vector(parts[a$cnt - 3], a$sub1), ".");
            a$subs = get_subs(parts);
            }
        }
    return a;
    }
    
event connection_state_remove(c: connection) &priority=10
    {
    if ( c?$dns && ! c$dns?$labels )
        {
        c$dns$labels = labels();
        if ( query_test(c$dns) )
            {
            local dl = get_labels(c$dns$query);
            if ( dl?$tld )
                c$dns$labels$tld = dl$tld;
            if ( dl?$first ) 
                c$dns$labels$lowest = dl$first;
            if ( dl?$sub1 ) 
                c$dns$labels$lvl2 = dl$sub1;
            if ( dl?$subs ) 
                c$dns$labels$subs = dl$subs;
            if ( dl?$cnt ) 
                c$dns$labels$cnt = dl$cnt;
            }
        }
    }