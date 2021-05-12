# "Community ID" flow hashing for Zeek

This Zeek package provides support for "community ID" flow hashing, a
standardized way of labeling traffic flows in network monitors. When
loaded, the package adds a `community_id` string field to
conn.log. This is work in progress between the Zeek and Suricata
communities, to enable correlation of flows in the outputs of both
tools. Feedback is very welcome, also from users/developers of other
monitoring software.

This package implements a BiF to implement the hashing logic and thus
needs binary compilation, so it's also a Zeek plugin. Here's an example
of a resulting conn.log:

```
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   conn
#open   2018-01-31-13-06-56
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   service duration        orig_bytes      resp_bytes      conn_state      local_orig      local_resp      missed_bytes    history orig_pkts       orig_ip_bytes   resp_pkts       resp_ip_bytes   tunnel_parents  community_id
#types  time    string  addr    port    addr    port    enum    string  interval        count   count   string  bool    bool    count   string  count   count   count   count   set[string]     string
1071580904.891921       CPcWB54kqKkvkdNEXe      128.232.110.120 34855   66.35.250.204   80      tcp     -       0.311104        496     1731    SF      -       -       2227    ShADadfF        6       816     6       2051    -       1:LQU9qZlK+B5F3KDmev6m5PMibrg=
#close  2018-01-31-13-06-56
```

## Protocol support

The Community ID spec currently envisions support for a number of
protocol constellations for which Zeek does not track flow-level state
because its analyzers wouldn't know what to do with the traffic. For
such flows Zeek never triggers the connection-related events used by
the package, so there won't be output in conn.log anyway. (If there
were protocols Zeek tracks at the flow level but the plugin doesn't
support, the reported ID would be empty.)  We currently support TCP
and UDP over IPv4 or IPv6, as well as ICMPv4 and ICMPv6. We do _not_
support other transport-level protocols (such as SCTP), or general
IP-address-pair flows for unsupported transport layer protocols.

## Using the package

The package's name is `bro-community-id`; the plugin's name is
`Corelight::CommunityID`. You can see the package's configuration
options in the corresponding [Zeek policy](scripts/Corelight/CommunityID/__load__.bro).

## Testing

The package includes btests that verify plugin loading and crunch
included test pcaps through Zeek to check baselined Zeek console output.

## Contact

For questions and feedback, please get in touch on the Zeek mailing
list, or contact Christian Kreibich (christian@corelight.com).
