# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.controller.handler import CONFIG_DISPATCHER
import networkx as nx
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

TRUNK_PORTS = (1, 7)
DEBUG = False


left_router_arp_table = {
	'192.168.1.2': '00:00:00:00:01:02',
	'192.168.1.3': '00:00:00:00:01:03',
	'192.168.1.4': '00:00:00:00:01:04',
	'192.168.1.5': '00:00:00:00:01:05'
}

right_router_arp_table = {
	'192.168.2.2': '00:00:00:00:02:02',
	'192.168.2.3': '00:00:00:00:02:03',
	'192.168.2.4': '00:00:00:00:02:04',
	'192.168.2.5': '00:00:00:00:02:05'
}

switch_ports = {
	2: {
		'trunk_ports': TRUNK_PORTS,
		'access_ports_100': (2, 3),
		'access_ports_200': (4, 5, 6)
	},
	3: {
		'trunk_ports': TRUNK_PORTS,
		'access_ports_100': (4, 5, 6),
		'access_ports_200': (2, 3)
	}
}


class SimpleSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch, self).__init__(*args, **kwargs)
		self.vlan_100_mac_to_port 			= {} 	# Used for VLAN 100 
		self.vlan_200_mac_to_port 			= {}	# Used for VLAN 200
		self.topology_api_app = self
		self.net = nx.DiGraph()
		
	def add_flow(self, datapath, match, actions):
		ofproto = datapath.ofproto

		mod = datapath.ofproto_parser.OFPFlowMod(
			datapath=datapath, match=match, cookie=0,
			command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
			priority=ofproto.OFP_DEFAULT_PRIORITY,
			flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions
		)

		datapath.send_msg(mod)

	def send_arp_reply(self, actions, datapath, src_mac_str, dst_mac_str, src_ip_str, dst_ip_str):
		self.logger.info("\033[32mARP Reply: [%s %s] -> [%s %s]\033[00m", 
			src_mac_str, src_ip_str, dst_mac_str, dst_ip_str)

		ofproto = datapath.ofproto
		# Create a Reply Packet
		reply_pkt = packet.Packet()
		reply_pkt.add_protocol(ethernet.ethernet(
			ethertype=ether.ETH_TYPE_ARP, dst=dst_mac_str, src=src_mac_str))
		reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac_str,
							   src_ip=src_ip_str, dst_mac=dst_mac_str, dst_ip=dst_ip_str))

		reply_pkt.serialize()

		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
			actions=actions, data=reply_pkt.data
		)

		datapath.send_msg(out)

	# Proactive
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		dpid = msg.datapath_id

		if dpid == 0x1A or dpid == 0x1B:
			if dpid == 0x1A:
				match = datapath.ofproto_parser.OFPMatch(
					dl_type=ether_types.ETH_TYPE_IP, nw_dst='192.168.2.0', nw_dst_mask=24, nw_tos=8)
				actions = [
					datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:01"),
					datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:02"),
					datapath.ofproto_parser.OFPActionOutput(4)
				]
			elif dpid == 0x1B:
				match = datapath.ofproto_parser.OFPMatch(
					dl_type=ether_types.ETH_TYPE_IP, nw_dst='192.168.1.0', nw_dst_mask=24, nw_tos=8)
				actions = [
					datapath.ofproto_parser.OFPActionSetDlSrc(
						"00:00:00:00:05:02"),
					datapath.ofproto_parser.OFPActionSetDlDst(
						"00:00:00:00:05:01"),
					datapath.ofproto_parser.OFPActionOutput(4)
				]

			self.add_flow(datapath, match, actions)
		

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		dpid = datapath.id
		ofproto = datapath.ofproto

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)

		dst = eth.dst
		src = eth.src
		ethertype = eth.ethertype

		# Initialize MAC to port tables as empty
		self.vlan_100_mac_to_port.setdefault(dpid, {})
		self.vlan_200_mac_to_port.setdefault(dpid, {})


		# Ignore Multicast Packets except Broadcast
		if (not int(dst.split(':')[0], 16) % 2 or dst == 'ff:ff:ff:ff:ff:ff') and not DEBUG:	
			self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)
		elif DEBUG:
			self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

		
		if dpid == 0x1A:
			if ethertype == ether_types.ETH_TYPE_ARP:
				# ARP Packet
				arp_pkt = pkt.get_protocol(arp.arp)
				if arp_pkt.opcode == arp.ARP_REQUEST:
					# ARP Packet must be destined for router
					if arp_pkt.dst_ip != '192.168.1.1':
						return

					actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)]
					self.send_arp_reply(actions, datapath, "00:00:00:00:01:01", src, arp_pkt.dst_ip, arp_pkt.src_ip)
				return

			elif ethertype == ether_types.ETH_TYPE_IP:
				# IP Packet
				ip_pkt = pkt.get_protocol(ipv4.ipv4)
				if '192.168.2.' in ip_pkt.dst:
					actions = [
						datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:01"),
						datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:02"),
						datapath.ofproto_parser.OFPActionOutput(1)
					]
					dst_ip_mask = 24

				elif '192.168.1.' in ip_pkt.dst and ip_pkt.dst in left_router_arp_table:
					actions = [
						datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:01:01"),
						datapath.ofproto_parser.OFPActionSetDlDst(left_router_arp_table[ip_pkt.dst]),
						datapath.ofproto_parser.OFPActionOutput(2)
					]
					dst_ip_mask = 32
				else:
					# Exclude Ethernet Header
					data = msg.data[14:]
					
					# Message was not received from the other router
					if msg.in_port != 1 and  msg.in_port != 4:
						src_mac = '00:00:00:00:01:01'
						dst_mac = eth.src
						src_ip = '192.168.1.1'
						out_port = 2
					
					# Message was received from the other router and this router does not
					# have an ARP entry for the destination MAC
					else:
						src_mac = '00:00:00:00:05:01' 	# PLACEHOLDER MUST CHANGE
						dst_mac = '00:00:00:00:05:02'	# PLACEHOLDER MUST CHANGE
						src_ip = '192.168.1.1' 			# PLACEHOLDER MUST CHANGE
						out_port = msg.in_port
					

					# Create ICMP Packet
					icmp_reply = packet.Packet()
					icmp_reply.add_protocol(ethernet.ethernet(
						ethertype=ethertype, dst=dst_mac, src=src_mac))
					icmp_reply.add_protocol(ipv4.ipv4(dst=ip_pkt.src, src=src_ip, proto=inet.IPPROTO_ICMP))
					icmp_reply.add_protocol(icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE,
													  data=icmp.dest_unreach(data_len=len(data), data=data)))
					icmp_reply.serialize()

					actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

					# Send Packet to Router
					out = datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
						actions=actions, data=icmp_reply.data)
					datapath.send_msg(out)

					return

				# Send Packet to Router
				out = datapath.ofproto_parser.OFPPacketOut(
					datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
					actions=actions, data=pkt.data)
				datapath.send_msg(out)

				match = datapath.ofproto_parser.OFPMatch(
					dl_type=ether_types.ETH_TYPE_IP, nw_dst=ip_pkt.dst, nw_dst_mask=dst_ip_mask)
				self.add_flow(datapath, match, actions)

				return
			return

		
		if dpid == 0x1B:
			if ethertype == ether_types.ETH_TYPE_ARP:  # this packet is ARP packet
				# ARP Packet
				arp_pkt = pkt.get_protocol(arp.arp)
				if arp_pkt.opcode == arp.ARP_REQUEST:
					# ARP Packet must be destined for router
					if arp_pkt.dst_ip != '192.168.2.1':
						return

					actions = [
						datapath.ofproto_parser.OFPActionOutput(msg.in_port)]
					self.send_arp_reply(
						actions, datapath, "00:00:00:00:02:01", src, arp_pkt.dst_ip, arp_pkt.src_ip)
				return

			elif ethertype == ether_types.ETH_TYPE_IP:
				# IP Packet
				ip_pkt = pkt.get_protocol(ipv4.ipv4)
				if '192.168.1.' in ip_pkt.dst:
					actions = [
						datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:02"),
						datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:01"),
						datapath.ofproto_parser.OFPActionOutput(1)
					]
					dst_ip_mask = 24

				elif '192.168.2.' in ip_pkt.dst and ip_pkt.dst in right_router_arp_table:
					actions = [
						datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:02:01"),
						datapath.ofproto_parser.OFPActionSetDlDst(right_router_arp_table[ip_pkt.dst]),
						datapath.ofproto_parser.OFPActionOutput(2)
					]

					dst_ip_mask = 32
				else:
					# Exclude Ethernet Header
					data = msg.data[14:]
					
					# Message was not received from the other router
					if msg.in_port != 1 and msg.in_port != 4:
						src_mac = '00:00:00:00:02:01'
						dst_mac = eth.src
						src_ip = '192.168.2.1'
						out_port = 2
					
					# Message was received from the other router and this router does not
					# have an ARP entry for the destination MAC
					else:
						src_mac = '00:00:00:00:05:02'	# PLACEHOLDER MUST CHANGE
						dst_mac = '00:00:00:00:05:01'	# PLACEHOLDER MUST CHANGE
						src_ip = '192.168.2.1' 			# PLACEHOLDER MUST CHANGE
						out_port = msg.in_port
					

					# Create ICMP Packet
					icmp_reply = packet.Packet()
					icmp_reply.add_protocol(ethernet.ethernet(
						ethertype=ethertype, dst=dst_mac, src=src_mac))
					icmp_reply.add_protocol(ipv4.ipv4(dst=ip_pkt.src, src=src_ip, proto=inet.IPPROTO_ICMP))
					icmp_reply.add_protocol(icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE,
													  data=icmp.dest_unreach(data_len=len(data), data=data)))
					icmp_reply.serialize()

					actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

					# Send Packet to Router
					out = datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
						actions=actions, data=icmp_reply.data)
					datapath.send_msg(out)

					return

				# Send Packet to Router
				out = datapath.ofproto_parser.OFPPacketOut(
					datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
					actions=actions, data=pkt.data)
				datapath.send_msg(out)

				match = datapath.ofproto_parser.OFPMatch(
					dl_type=ether_types.ETH_TYPE_IP, nw_dst=ip_pkt.dst, nw_dst_mask=dst_ip_mask)
				self.add_flow(datapath, match, actions)

				return
			return

		
		# Circle Detection on Trunk Port
		if eth.src not in self.net:
			self.net.add_node(src)
			self.net.add_edge(dpid, src, ports=[msg.in_port])
			self.net.add_edge(src, dpid)
		
		if eth.dst not in self.net and eth.src:
			# The shortest path is computed based on the source and destination of the packet.
			# The shortest path in this case indicates the hops needed to reach current dpid.
			# When the in port is not the same as the shortest path suggest a loop is detected.
			# Try/Except is used here to handle incomplete topologies (topologies that are not yet 
			# completely constructed) 
			try:
				path = nx.shortest_path(self.net, eth.src, dpid)
			except:
				return

			port_in_shortest_path = False
			for node in path:
				# Node might not exists (LLDP Packets and Multicast) 
				if node not in self.net[dpid]:
					continue
				
				# The port that the packet was received from is not in the shortest path
				# Continue since another hop might be needed.
				if msg.in_port not in self.net[dpid][node]['ports']:
					continue
				
				port_in_shortest_path = True
				break
			
			# In port is not on shortest path thus abort to avoid 
			# further unessecary flooding
			if not port_in_shortest_path:
				if (not int(dst.split(':')[0], 16) % 2 or dst == 'ff:ff:ff:ff:ff:ff') and not DEBUG:
					self.logger.info("\033[31mLoop Detected in %s %s %s %s in_port=%s\033[00m", 
						hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)
				return
				


		# Add port to avoid flooding next time
		if msg.in_port in switch_ports[dpid]['access_ports_100'] and \
			eth.src not in self.vlan_100_mac_to_port[dpid]:

				# Add MAC-Port for VLAN 100
				self.vlan_100_mac_to_port[dpid][eth.src] = msg.in_port
	
		elif msg.in_port in switch_ports[dpid]['access_ports_200'] and \
			eth.src not in self.vlan_200_mac_to_port[dpid]:

			# Add MAC-Port for VLAN 200
			self.vlan_200_mac_to_port[dpid][eth.src] = msg.in_port
		else:
			# VLAN Packet
			if ethertype == ether_types.ETH_TYPE_8021Q:
				# VLAN Header
				vlan_pkt = pkt.get_protocol(vlan.vlan)

				if vlan_pkt.vid == 100:
					self.vlan_100_mac_to_port[dpid][eth.src] = msg.in_port
				else:
					self.vlan_200_mac_to_port[dpid][eth.src] = msg.in_port
			

		out_ports = []
		detected_vlan = None # Detected VLAN
		flood = False # Flood flag used for flows (matches)
		strip_vlan = False # Flag that indicates the source port 
		
		# VLAN 100 Access Port
		if msg.in_port in switch_ports[dpid]['access_ports_100']:
			detected_vlan = 100
			# Send to the known destination directly
			if eth.dst in self.vlan_100_mac_to_port[dpid]:
				out_ports = [self.vlan_100_mac_to_port[dpid][dst]] 
			
			# Output port not found thus FLOOD to VLAN 100
			else:
				# Flood all VLAN 100 access ports except in-port
				for access_port in switch_ports[dpid]['access_ports_100']:
					if access_port != msg.in_port:
						out_ports.append(access_port)
				
				# Also send to trunk ports
				for trunk_port in switch_ports[dpid]['trunk_ports']:
					out_ports.append(trunk_port)
				
				# Flooding Flag
				flood = True
		
		# VLAN 200 Access Port
		elif msg.in_port in switch_ports[dpid]['access_ports_200']:
			detected_vlan = 200
			# Send to the known destination directly
			if eth.dst in self.vlan_200_mac_to_port[dpid]:
				out_ports = [self.vlan_200_mac_to_port[dpid][dst]] 
			
			# Output port not found thus FLOOD to VLAN 200
			else:
				# Flood all VLAN 100 access ports except in-port
				for access_port in switch_ports[dpid]['access_ports_200']:
					if access_port != msg.in_port:
						out_ports.append(access_port)
				
				# Also send to trunk port
				for trunk_port in switch_ports[dpid]['trunk_ports']:
					out_ports.append(trunk_port)

				# Flooding Flag
				flood = True

		# VLAN 100 or 200 Trunk Port
		else:
			if ethertype == ether_types.ETH_TYPE_8021Q:
				# VLAN Header
				vlan_pkt = pkt.get_protocol(vlan.vlan)
				detected_vlan = vlan_pkt.vid
			
				# VLAN 100
				if vlan_pkt.vid == 100:
					# Send to the known destination directly
					if eth.dst in self.vlan_100_mac_to_port[dpid]:
						out_ports = [self.vlan_100_mac_to_port[dpid][dst]]
					# Output port not found thus FLOOD to VLAN 100
					else: 
						out_ports.extend(switch_ports[dpid]['access_ports_100'])
						out_ports.extend([x for x in switch_ports[dpid]['trunk_ports'] if x != msg.in_port])
						flood = True
				
				# VLAN 200
				elif vlan_pkt.vid == 200:
					# Send to the known destination directly
					if eth.dst in self.vlan_200_mac_to_port[dpid]:
						out_ports = [self.vlan_200_mac_to_port[dpid][dst]] 
					
					# Output port not found thus FLOOD to VLAN 200
					else:
						out_ports.extend(switch_ports[dpid]['access_ports_200'])
						out_ports.extend([x for x in switch_ports[dpid]['trunk_ports'] if x != msg.in_port])
						flood = True

				# VLAN header must be removed
				strip_vlan = True
			
			# Multicast packets that hosts produce for discovery
			# thus the VLAN header is not set by host. In this case,
			# the out_ports and the actions will be empty and thus the
			# packet must be droped (flow is added with no actions)
			else: 
				match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=eth.dst)
				self.add_flow(datapath, match, [])
				return
		
		# Data to send
		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data
		
		actions = []
		for out_port in out_ports:
			# Remove VLAN header. The trunk port will never be included in the
			# output ports if this value is true. This value indicates a direction 
			# from the trunk port to the access ports and not the opposite. 
			if strip_vlan:
				actions.append(datapath.ofproto_parser.OFPActionStripVlan())
			
			# Add output port
			if out_port not in TRUNK_PORTS:
				actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
			
			# Add VLAN header and send to trunk port
			else:
				actions.append(datapath.ofproto_parser.OFPActionVlanVid(detected_vlan))
				actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))

		
		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
			actions=actions, data=data)
		datapath.send_msg(out)

		# # Packet has a destination MAC. Flood packets must be ignored
		if flood:
			return
		
		# This variable (strip_vlan) indicates a direction from trunk to access ports
		if strip_vlan:
			match = datapath.ofproto_parser.OFPMatch(dl_vlan=vlan_pkt.vid, in_port=msg.in_port, dl_dst=eth.dst)
		else:
			match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=eth.dst)
		
		self.add_flow(datapath, match, actions)
	


	# Helper function to add source to destination links
	def add_links_src_dst(self, links_list):
		links = []
		for outer_link in links_list:
			link_exists = False
			for inner_link in links:
				if outer_link.src.dpid != inner_link[0] or outer_link.dst.dpid != inner_link[1]:
					continue
				
				if outer_link.src.port_no not in inner_link[2]['ports']:
					inner_link[2]['ports'].append(outer_link.src.port_no)
				link_exists = True
			
			if not link_exists:
				links.append((outer_link.src.dpid, outer_link.dst.dpid, {'ports':[outer_link.src.port_no]}))

		return links


	# Helper function to add destination to source links
	def add_links_dst_src(self, links_list):
		links = []
		for outer_link in links_list:
			link_exists = False
			for inner_link in links:
				if outer_link.dst.dpid != inner_link[0] or outer_link.src.dpid != inner_link[1]:
					continue
				
				if outer_link.dst.port_no not in inner_link[2]['ports']:
					inner_link[2]['ports'].append(outer_link.dst.port_no)
				link_exists = True
			
			if not link_exists:
				links.append((outer_link.dst.dpid, outer_link.src.dpid, {'ports':[outer_link.src.port_no]}))

		return links


	
	# Unlike before an edge (connecting two dpids) can have multiple ports 
	# Example: dpids 2 - 3 are connected with both ports 1 and 7 and both ports must be
	# stored (unlike previously where the first port was replace by the second one)
	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]
		self.net.add_nodes_from(switches)

		links_list = get_link(self.topology_api_app, None)
		
		# Source to destination
		links = self.add_links_src_dst(links_list)
		self.net.add_edges_from(links)

		# Destination to source
		links = self.add_links_dst_src(links_list)
		self.net.add_edges_from(links)
		
		if DEBUG:
			print("********** List of Links **********")
			print(self.net.edges())


	@set_ev_cls(event.EventLinkAdd)
	def print_link(self, ev):
		links_list = get_link(self.topology_api_app, None)
		
		# Source to destination
		links = self.add_links_src_dst(links_list)
		self.net.add_edges_from(links)


		# Destination to source
		links = self.add_links_dst_src(links_list)
		self.net.add_edges_from(links)
		
		if DEBUG:
			print("********** List of Links **********")
			print(self.net.edges())
		

	@set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
	def _port_status_handler(self, ev):
		msg = ev.msg
		reason = msg.reason
		port_no = msg.desc.port_no

		ofproto = msg.datapath.ofproto
		if reason == ofproto.OFPPR_ADD:
			self.logger.info("port added %s", port_no)
		elif reason == ofproto.OFPPR_DELETE:
			self.logger.info("port deleted %s", port_no)
		elif reason == ofproto.OFPPR_MODIFY:
			self.logger.info("port modified %s", port_no)
		else:
			self.logger.info("Illeagal port state %s %s", port_no, reason)
