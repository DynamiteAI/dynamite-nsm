
#include "zeek-config.h"

#include "AF_Packet.h"
#include "RX_Ring.h"

#include "af_packet.bif.h"

using namespace iosource::pktsrc;

AF_PacketSource::~AF_PacketSource()
	{
	Close();
	}

AF_PacketSource::AF_PacketSource(const std::string& path, bool is_live)
	{
	if ( ! is_live )
		Error("AF_Packet source does not support offline input");

	current_filter = -1;
	props.path = path;
	props.is_live = is_live;
	}

void AF_PacketSource::Open()
	{
	uint64_t buffer_size = BifConst::AF_Packet::buffer_size;
	bool enable_hw_timestamping = BifConst::AF_Packet::enable_hw_timestamping;
	bool enable_fanout = BifConst::AF_Packet::enable_fanout;

	socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if ( socket_fd < 0 )
		{
		Error(errno ? strerror(errno) : "unable to create socket");
		return;
		}

	// Create RX-ring
	try {
		rx_ring = new RX_Ring(socket_fd, buffer_size);
	} catch (RX_RingException& e) {
		Error(errno ? strerror(errno) : "unable to create RX-ring");
		close(socket_fd);
		return;
	}

	// Setup interface
	if ( ! BindInterface() )
		{
		Error(errno ? strerror(errno) : "unable to bind to interface");
		close(socket_fd);
		return;
		}

	if ( ! EnablePromiscMode() )
		{
		Error(errno ? strerror(errno) : "unable enter promiscious mode");
		close(socket_fd);
		return;
		}

	if ( ! ConfigureFanoutGroup(enable_fanout) )
		{
		Error(errno ? strerror(errno) : "failed to join fanout group");
		close(socket_fd);
		return;
		}

	if ( ! ConfigureHWTimestamping(enable_hw_timestamping) )
		{
		Error(errno ? strerror(errno) : "failed to configure hardware timestamping");
		close(socket_fd);
		return;
		}

	props.netmask = NETMASK_UNKNOWN;
	props.selectable_fd = socket_fd;
	props.is_live = true;
	props.link_type = DLT_EN10MB; // Ethernet headers

	stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
	num_discarded = 0;

	Opened(props);
	}

inline bool AF_PacketSource::BindInterface()
	{
	struct ifreq ifr;
	struct sockaddr_ll saddr_ll;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", props.path.c_str());

	ret = ioctl(socket_fd, SIOCGIFINDEX, &ifr);
	if ( ret < 0 )
		return false;

	memset(&saddr_ll, 0, sizeof(saddr_ll));
	saddr_ll.sll_family = AF_PACKET;
	saddr_ll.sll_protocol = htons(ETH_P_ALL);
	saddr_ll.sll_ifindex = ifr.ifr_ifindex;

	ret = bind(socket_fd, (struct sockaddr *) &saddr_ll, sizeof(saddr_ll));
	return (ret >= 0);
	}

inline bool AF_PacketSource::EnablePromiscMode()
	{
	struct ifreq ifr;
	struct packet_mreq mreq;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", props.path.c_str());

	ret = ioctl(socket_fd, SIOCGIFINDEX, &ifr);
	if ( ret < 0 )
		return false;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = ifr.ifr_ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;

	ret = setsockopt(socket_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	return (ret >= 0);
	}

inline bool AF_PacketSource::ConfigureFanoutGroup(bool enabled)
	{
	if ( enabled )
		{
		uint32_t fanout_arg, fanout_id;
		int ret;

		fanout_id = BifConst::AF_Packet::fanout_id;
		fanout_arg = ((fanout_id & 0xffff) | (GetFanoutMode() << 16));

		ret = setsockopt(socket_fd, SOL_PACKET, PACKET_FANOUT,
			&fanout_arg, sizeof(fanout_arg));

		if ( ret < 0 )
			return false;
		}
	return true;
	}

inline bool AF_PacketSource::ConfigureHWTimestamping(bool enabled)
	{
	if ( enabled )
		{
		struct ifreq ifr;
		struct hwtstamp_config hwts_cfg;
		int ret, opt;

		memset(&hwts_cfg, 0, sizeof(hwts_cfg));
		hwts_cfg.tx_type = HWTSTAMP_TX_OFF;
		hwts_cfg.rx_filter = HWTSTAMP_FILTER_ALL;
		memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", props.path.c_str());
		ifr.ifr_data = &hwts_cfg;

		ret = ioctl(socket_fd, SIOCSHWTSTAMP, &ifr);
		if ( ret < 0 )
			return false;

		opt = SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE;
		ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TIMESTAMP,
			&opt, sizeof(opt));
		if( ret < 0 )
			return false;
		}
	return true;
	}

inline uint32_t AF_PacketSource::GetFanoutMode()
	{
	switch ( BifConst::AF_Packet::fanout_mode->AsEnum() ) {
		case BifEnum::AF_Packet::FANOUT_CPU: return PACKET_FANOUT_CPU;
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
		case BifEnum::AF_Packet::FANOUT_QM: return PACKET_FANOUT_QM;
	#endif
		default: return PACKET_FANOUT_HASH;
	}
	}

void AF_PacketSource::Close()
	{
	if ( ! socket_fd )
		return;

	delete rx_ring;
	close(socket_fd);
	socket_fd = 0;

	Closed();
	}

bool AF_PacketSource::ExtractNextPacket(Packet* pkt)
	{
	if ( ! socket_fd )
		return false;

	struct tpacket3_hdr *packet = 0;
	const u_char *data;
	struct timeval ts;
	while ( true )
		{
		if ( ! rx_ring->GetNextPacket(&packet) )
			return false;

		current_hdr.ts.tv_sec = packet->tp_sec;
		current_hdr.ts.tv_usec = packet->tp_nsec / 1000;
		current_hdr.caplen = packet->tp_snaplen;
		current_hdr.len = packet->tp_len;
		data = (u_char *) packet + packet->tp_mac;

		if ( !ApplyBPFFilter(current_filter, &current_hdr, data) )
			{
			++num_discarded;
			DoneWithPacket();
			continue;
			}

		pkt->Init(props.link_type, &current_hdr.ts, current_hdr.caplen, current_hdr.len, data);

		if ( current_hdr.len == 0 || current_hdr.caplen == 0 )
			{
			Weird("empty_af_packet_header", pkt);
			return false;
			}

		stats.received++;
		stats.bytes_received += current_hdr.len;
		return true;
		}

	return false;
	}

void AF_PacketSource::DoneWithPacket()
	{
	rx_ring->ReleasePacket();
	}

bool AF_PacketSource::PrecompileFilter(int index, const std::string& filter)
	{
	return PktSrc::PrecompileBPFFilter(index, filter);
	}

bool AF_PacketSource::SetFilter(int index)
	{
	current_filter = index;
	return true;
	}

void AF_PacketSource::Statistics(Stats* s)
	{
	if ( ! socket_fd )
		{
		s->received = s->bytes_received = s->link = s->dropped = 0;
		return;
		}

	struct tpacket_stats_v3 tp_stats;
	socklen_t tp_stats_len = sizeof (struct tpacket_stats_v3);
	int ret;

	ret = getsockopt(socket_fd, SOL_PACKET, PACKET_STATISTICS, &tp_stats, &tp_stats_len);
	if ( ret < 0 )
		{
		Error(errno ? strerror(errno) : "unable to retrieve statistics");
		s->received = s->bytes_received = s->link = s->dropped = 0;
		return;
		}

	stats.link += tp_stats.tp_packets;
	stats.dropped += tp_stats.tp_drops;

	memcpy(s, &stats, sizeof(Stats));
	}

iosource::PktSrc* AF_PacketSource::InstantiateAF_Packet(const std::string& path, bool is_live)
	{
	return new AF_PacketSource(path, is_live);
	}
