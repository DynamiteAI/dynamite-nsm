# @TEST-EXEC: for pcap in $(cd $TRACES && ls *.pcap); do bro -r $TRACES/$pcap %INPUT >$pcap.out; done
# @TEST-EXEC: for pcap in $(cd $TRACES && ls *.pcap); do btest-diff $pcap.out; done

# Loading the plugin in the following way seems to work both in the
# local testing done by bro-pkg at installation time, and when running
# later. --cpk
@load Corelight/CommunityID

# We need to enable verbose logging to get the baseline output.
redef CommunityID::verbose=T;
