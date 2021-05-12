# This script calculates and adds PCR to the conn log. By default
# this is done using Zeek's calculated application bytes, but 
# can be configured to use the IP header's length field instead. 

export {
    const use_ip_length: bool = F &redef;
    redef record Conn::Info += {
        pcr: double &optional &log;
    };
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
    switch use_ip_length 
        {
            case F:
                # Use Zeek's calculated application byte values.
                # There are known issues with this approach but it 
                # avoids header length discrepancies caused by using 
                # the more reliable IP length field. 
                if ( ! c$orig?$size || ! c$resp?$size ) {
                    # both bytes fields must be initialized
                    return;
                }
                # PCR is a measure of data transfer, if no data 
                # was transferred, e.g. 0 app bytes, it can't be 
                # calculated.
                else if (c$orig$size == 0 && c$resp$size == 0 ) {
                    return;   
                }
                else {
                    c$conn$pcr = calc_pcr(c$orig$size, c$resp$size);
                }
                break; 
            case T:
                # Use the IP length header. 
                # We do some sanity checking to help ensure there was some data transfer.
                # This is not a gaurauntee however, TCP can have up to 40 additional 
                # bytes in options included in the header. We can't see that from here.
                # For tcp, must be >20 bytes sent or received (minimum tcp header length) 
                # For udp, must be >8 bytes sent or received (minimum udp header length)
                if ( c$conn?$proto && c$orig?$num_bytes_ip && c$resp?$num_bytes_ip )
                    {
                    switch c$conn$proto 
                        {
                        case udp:
                            if ( c$orig$num_bytes_ip > 8 || c$resp$num_bytes_ip > 8 )
                                {
                                c$conn$pcr = calc_pcr(c$orig$num_bytes_ip, c$resp$num_bytes_ip);    
                                }
                            break;
                        case tcp:
                            if ( c$orig$num_bytes_ip > 20 || c$resp$num_bytes_ip > 20 )
                                {
                                c$conn$pcr = calc_pcr(c$orig$num_bytes_ip, c$resp$num_bytes_ip);    
                                }
                            break;
                        }
                    }
                break;   
        }   
}