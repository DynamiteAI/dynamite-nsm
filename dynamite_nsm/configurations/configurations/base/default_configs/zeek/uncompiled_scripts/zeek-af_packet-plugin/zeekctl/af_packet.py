import ZeekControl.plugin

class AF_Packet(ZeekControl.plugin.Plugin):
	def __init__(self):
		super(AF_Packet, self).__init__(apiversion=1)

	def name(self):
		return "af_packet"

	def pluginVersion(self):
		return 1

	def init(self):
		# Only use the plugin if there is a worker using AF_PACKET for load balancing.
		for nn in self.nodes():
			if nn.type == "worker" and nn.interface.startswith("af_packet::") and nn.lb_procs:
				return True

		return False

	def nodeKeys(self):
		return ["fanout_id", "fanout_mode", "buffer_size"]

	def zeekctl_config(self):
		script = ""

		# Add custom configuration values per worker.
		for nn in self.nodes():
			if nn.type != "worker" or not nn.lb_procs:
				continue

			params = ""

			if nn.af_packet_fanout_id:
				params += "\n  redef AF_Packet::fanout_id = %s;" % nn.af_packet_fanout_id
			if nn.af_packet_fanout_mode:
				params += "\n  redef AF_Packet::fanout_mode = %s;" % nn.af_packet_fanout_mode
			if nn.af_packet_buffer_size:
				params += "\n  redef AF_Packet::buffer_size = %s;" % nn.af_packet_buffer_size

			if params:
				script += "\n@if( peer_description == \"%s\" ) %s\n@endif" % (nn.name, params)

		return script
