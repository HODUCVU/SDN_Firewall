from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls, DEAD_DISPATCHER
# from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_0, ofproto_v1_2, ofproto_v1_3
from ryu.ofproto import ofproto_v1_0_parser, ofproto_v1_2_parser, ofproto_v1_3_parser
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp, tcp, icmp
from ryu.ofproto.ether import ETH_TYPE_IP, ETH_TYPE_ARP, ETH_TYPE_LLDP, ETH_TYPE_MPLS, ETH_TYPE_IPV6
from ryu.ofproto.inet import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP
# custom lib 
# from parse_firewall_rules import parse_firewall 
from ParseFirewallFromDB import ParseFirewallFromDB
from switch_information import SwitchInfo
from packet_out import SendPacket
from construct_flow import Construct 
from connection_tracking import TrackConnection

from collections import defaultdict
from ryu.lib import hub
import time
from ryu.lib import dpid as dpid_lib
from ctrlapi import CtrlApi

ICMP_PING = 8
ICMP_PONG = 0
# hping3 -c 10 -k -s source_port -p destination_port -A dst_ip
TCP_SYN = 0x02 # -S
# hping3 -c 10 -k -s source_port -p destination_port -SA dst_ip
TCP_SYN_ACK = 0x12 # -SA
TCP_BOGUS_FLAGS = 0x15 #0x0F <here>

class SecureFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"dpset": dpset.DPSet}


    database = ParseFirewallFromDB("dataset/firewall-drop.db")
    inner_policy = {}
    icmp_conn_track = {}
    tcp_conn_track = {}
    udp_conn_track = {}
    sendpkt = SendPacket()
    flow = Construct()
    track = TrackConnection()

    def __init__(self, *args, **kwargs):
        super(SecureFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.inner_policy = self.database.parse()

        self.dpset = kwargs["dpset"]
        self.ofctl = ofctl_v1_3
        self.ctrl_api = CtrlApi(self)
        self.msgs = {}

        # self.current_time = time.time()
        # self.last_time = self.current_time
        
        # Get avenger value of stats on switch_information
        self.total_packet = defaultdict(int)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        if self.inner_policy:
            self.logger.info("Firewall rules parsed successfully from the database.")
        else:
            self.logger.error("Failed to parse firewall rules from the database.")
        self.logger.info("dict is ready")
    # Get Stats
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                dpid_str = dpid_lib.dpid_to_str(dp.id)
                if  dpid_str[:2] == '00':
                    self._request_stats(dp)
            # current_time = time.time()
            # elapsed_time = current_time - self.last_time
            # self.totaltime += elapsed_time
            # print("on monitor: ", self.totaltime)
            # self.last_time = current_time
            hub.sleep(5)
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    # @set_ev_cls(
    #     [   ofp_event.EventOFPStatsReply,
    #         ofp_event.EventOFPDescStatsReply,
    #         ofp_event.EventOFPFlowStatsReply,
    #         ofp_event.EventOFPAggregateStatsReply,
    #         ofp_event.EventOFPTableStatsReply,
    #         # ofp_event.EventOFPTableFeaturesStatsReply,
    #         ofp_event.EventOFPPortStatsReply,
    #         # ofp_event.EventOFPQueueStatsReply,
    #         # ofp_event.EventOFPQueueDescStatsReply,
    #         ofp_event.EventOFPMeterStatsReply,
    #         ofp_event.EventOFPMeterFeaturesStatsReply,
    #         ofp_event.EventOFPMeterConfigStatsReply,
    #         ofp_event.EventOFPGroupStatsReply,
    #         # ofp_event.EventOFPGroupFeaturesStatsReply,
    #         ofp_event.EventOFPGroupDescStatsReply,
    #         ofp_event.EventOFPPortDescStatsReply,
    #     ],
    #     MAIN_DISPATCHER,
    # )
    # def stats_reply_handler(self, event):
    #     """Handles Reply Events"""
    #     msg = event.msg
    #     data_path = msg.datapath
    #
    #     if data_path.id not in self.ctrl_api.get_waiters():
    #         return
    #     if msg.xid not in self.ctrl_api.get_waiters()[data_path.id]:
    #         return
    #     lock, msgs = self.ctrl_api.get_waiters()[data_path.id][msg.xid]
    #     self.msgs.append(msg)
    #
    #     # self.logger("---------------------")
    #     # for m in msgs:
    #     #     self.logger(m)
    #     # self.logger("---------------------")
    #
    #     flags = data_path.ofproto.OFPMPF_REPLY_MORE
    #
    #     if msg.flags & flags:
    #         return
    #     del self.ctrl_api.get_waiters()[data_path.id][msg.xid]
    #     lock.set()
    # @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    @set_ev_cls(
        [   ofp_event.EventOFPStatsReply,
            ofp_event.EventOFPDescStatsReply,
            ofp_event.EventOFPFlowStatsReply,
            ofp_event.EventOFPAggregateStatsReply,
            ofp_event.EventOFPTableStatsReply,
            # ofp_event.EventOFPTableFeaturesStatsReply,
            ofp_event.EventOFPPortStatsReply,
            # ofp_event.EventOFPQueueStatsReply,
            # ofp_event.EventOFPQueueDescStatsReply,
            ofp_event.EventOFPMeterStatsReply,
            ofp_event.EventOFPMeterFeaturesStatsReply,
            ofp_event.EventOFPMeterConfigStatsReply,
            ofp_event.EventOFPGroupStatsReply,
            # ofp_event.EventOFPGroupFeaturesStatsReply,
            ofp_event.EventOFPGroupDescStatsReply,
            ofp_event.EventOFPPortDescStatsReply,
        ],
        MAIN_DISPATCHER,
    )
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
        try:
            self.logger.info('datapath         '
                            'in-port  '
                            'out-port packets  bytes')
            self.logger.info('---------------- '
                            '-------- '
                            '-------- -------- --------')
            for stat in sorted([flow for flow in body if flow.priority == 1001],
                               key=lambda flow: (flow.match.get('in_port', 0))):

                self.logger.info('%016x %8x %8x %8d %8d',
                                ev.msg.datapath.id,
                                stat.match['in_port'],# stat.match['eth_src'], stat.match['eth_dst'],
                                stat.instructions[0].actions[0].port,
                                stat.packet_count, stat.byte_count)

                self.total_packet[(stat.match['in_port'], stat.instructions[0].actions[0].port)] += 10
                # self.total_packet[(int(stat.match['ipv4_src']), int(stat.match['ipv4_dst']))] += 10
                print(stat.packet_count/self.total_packet[(stat.match['in_port'], stat.instructions[0].actions[0].port)])
                self.logger.info("Match: ")
                self.logger.info(stat.match)
                if(stat.packet_count / self.total_packet[(stat.match['in_port'], stat.instructions[0].actions[0].port)]) >= 3:
                    # Drop this packet here
                    actions = []
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, priority=1002, match=stat.match, instructions=inst)
                    datapath.send_msg(mod)

                    ipv4_src = stat.match.get('ipv4_src')
                    ipv4_dst = stat.match.get('ipv4_dst')
                    # in_port = stat.match.get('in_port')
                    # eth = stat.match.get('eth_type')
                    # ip_proto = stat.match.get('ip_proto')
                    self.logger.info("DROPED in --- in_port: {}, out_port: {}, IPv4_src: {}, IPv4_dst: {}".format(stat.match['in_port'], stat.instructions[0].actions[0].port, ipv4_src, ipv4_dst))

        except Exception as err:
            self.logger.info("ERROR in 140: %s", err)
    # <check behave>
    # <add extract header for this condition>
    # if(ipo.src not in self.inner_policy) or (ipo.dst not in self.inner_policy):
    #     self.total_packet[(ipo.src, ipo.dst)] += 1

    # print("totaltile: ", self.totaltime)
    # if(self.totaltime >= 1.0):
    # firewall_rules = [
    #     ("10.0.0.3", "10.0.0.4", "ICMP", None, None, "PING", "DROP"),
    #     ("10.0.0.1", "10.0.0.2", "TCP", 1000, 8080, "NEW", "ALLOW"),
    #     ]
    # self.totaltime = 0.0
    # print("------")
    # print("total packet from %s -> %s: " % (ipo.src, ipo.dst), self.total_packet[(ipo.src, ipo.dst)] )
    # print("------")
    # if self.total_packet[(ipo.src, ipo.dst)] >= 10:
    #     self.total_packet[(ipo.src, ipo.dst)] = 1
    #
    #     # self.total_packet.clear()
    #     #drop
    #     if ipo.proto == IPPROTO_ICMP:
    #         actions_default = action_drop #drop
    #         self.icmp_conn_track = self.track.conn_track_dict(self.icmp_conn_track,ipo.src, ipo.dst, "PING", "PONG", xyz[5],1)
    #         self.logger.info("%s -> %s: Oversend Package" % (ipo.src, ipo.dst))
    #         self.flow.add_flow(datapath=datapath, actions=actions_default, priority=1002, in_port=in_port,
    #                             eth_type=ETH_TYPE_IP, ip_proto=IPPROTO_ICMP, icmpv4_type=ICMP_PING, 
    #                             ipv4_src=ipo.src, ipv4_dst = ipo.dst)
    #     elif ipo.proto == IPPROTO_TCP:
    #         tcpo = pkt.get_protocol(tcp.tcp)
    #         actions_default = action_drop
    #         self.logger.info("%s -> %s : Oversend TCP Package" % (ipo.src, ipo.dst))
    #         self.tcp_conn_track = self.track.conn_track_dict(self.tcp_conn_track, ipo.src, ipo.dst, tcpo.src_port,
    #                                                             tcpo.dst_port, tcpo.seq, 1)
    #         self.flow.add_flow(datapath=datapath, actions=actions_default, priority = 1002, in_port=in_port,
    #                             eth_type = ETH_TYPE_IP, ip_proto= IPPROTO_TCP,
    #                             ipv4_src = ipo.src, ipv4_dst=ipo.dst,
    #                             tcp_src=tcpo.src_port, tcp_dst=tcpo.dst_port)
    
    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        SwitchInfo(ev)

    # Handles incoming packets. Decodes them and checks for suitable Firewall rules
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        # data = msg.data
        # print("data: ", len(data))
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        actions_default = []
        action_fwd_to_out_port = []

        try:
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            ethtype = eth.ethertype

            out_port = self.port_learn(datapath, eth, in_port)
            action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]

            action_fwd_to_out_port = [parser.OFPActionOutput(out_port)]
            actions_default = action_fwd_to_out_port

            if(out_port != ofproto.OFPP_FLOOD) and (ethtype == ETH_TYPE_IP):
                ipo = pkt.get_protocols(ipv4.ipv4)[0]
                # check for ICMP  
                if ipo.proto == IPPROTO_ICMP:
                    icmpob = pkt.get_protocol(icmp.icmp)
                    flag1 = 0 
                    # Check if this is ICMP_PING 
                    if ((icmpob.type==ICMP_PING) and (ipo.src in self.inner_policy)):
                        temp = self.inner_policy.get(ipo.src)
                        for i in range(0, len(temp)):
                            # print(temp[i][0])
                            if temp[i][0] == ipo.dst:
                                xyz = temp[i]
                                # <here>
                                # print(xyz[1->5])
                                if(xyz[1] == "ICMP") and (xyz[5] == 'DROP'): #--- column in firewall rules 
                                    flag1 = 1 
                                    actions_default = action_drop #drop
                                    self.icmp_conn_track = self.track.conn_track_dict(self.icmp_conn_track,ipo.src, ipo.dst, "PING", "PONG", xyz[5],1)
                                    self.logger.info("%s -> %s: Echo Request droped" % (ipo.src, ipo.dst))
                                    self.flow.add_flow(datapath=datapath, actions=actions_default, priority=1002, in_port=in_port,
                                                       eth_type=ETH_TYPE_IP, ip_proto=IPPROTO_ICMP, icmpv4_type=ICMP_PING, 
                                                       ipv4_src=ipo.src, ipv4_dst = ipo.dst)
                                    break
                    # Otherwise, ICMP_PONG 
                    elif (icmpob.type == ICMP_PONG) and (ipo.dst in self.icmp_conn_track):
                        tmp = self.icmp_conn_track.get(ipo.dst)
                        for i in range(0, len(tmp)):
                            # <here>
                            if tmp[i][0] == ipo.src:
                                xyz = tmp[i]
                                 # <here>
                                if(xyz[1] == 'PING') and (xyz[2] == 'PONG'):
                                    print("ICMP track PING")
                                    flag1 = 1
                                    actions_default = action_drop
                                    self.flow.add_flow(datapath = datapath, actions=actions_default,
                                                       priority=1002, in_port=in_port, eth_type=ETH_TYPE_IP,
                                                       ip_proto = IPPROTO_ICMP, icmpv4_type=ICMP_PONG,
                                                       ipv4_src=ipo.src, ipv4_dst=ipo.dst)
                                    self.icmp_conn_track = self.track.conn_track_dict(self.icmp_conn_track, ipo.src,
                                                                                      ipo.dst, "PONG", "PING",
                                                                                      xyz[3], 1)
                                    self.logger.info("\n%s -> %s action = PING, state = BLOCKED \n" % (ipo.dst, ipo.src))
                    # Time
                    # No match
                    if(flag1==0):
                        actions_default = action_fwd_to_out_port
                        self.flow.add_flow(datapath = datapath, actions=actions_default,
                                            priority=1001, in_port=in_port, eth_type=ETH_TYPE_IP,
                                            ip_proto = IPPROTO_ICMP, icmpv4_type=ICMP_PONG,
                                            ipv4_src=ipo.src, ipv4_dst=ipo.dst)

                        self.logger.info("%s -> %s : ALLOWED" %(ipo.src, ipo.dst))

                # Check for TCP  
                elif (ipo.proto == IPPROTO_TCP):
                    tcpo = pkt.get_protocol(tcp.tcp)
                    # tcp_payload = pkt.protocols[-1] 
                    print("--------")
                    print("tcp.bits: ", tcpo.bits, " -- TCP_SYN: ", TCP_SYN, "-- &: ", (tcpo.bits & TCP_SYN))
                    print("--------")
                    flag2 = 0 
                    # TCP SYN packet <here> 
                    if ((tcpo.bits & TCP_SYN) == TCP_SYN) and ((tcpo.bits & TCP_BOGUS_FLAGS) == 0x00):
                        print("TCP_SYN!!")
                        if ipo.src in self.inner_policy:
                            temp = self.inner_policy.get(ipo.src)
                            for i in range(0, len(temp)):
                                 # <here>
                                print("srcIP: ", ipo.src, " - dstIP: ", temp[i][0], " -- Protocol: ", temp[i][1], " -- srcPort: ", temp[i][2], " dstPort: ", temp[i][3])
                                print("srcIP: ", ipo.src, " - dstIP: ", ipo.dst, " -- Protocol: Nocheck", " -- srcPort: ", tcpo.src_port, " dstPort: ", tcpo.dst_port)
                                if((temp[i][0] == ipo.dst) and (temp[i][1] == 'TCP') and (int(temp[i][2]) == tcpo.src_port) and (int(temp[i][3]) == tcpo.dst_port)
                                       and (temp[i][5] == 'DROP')):
                                    flag2 = 1 
                                    actions_default = action_drop
                                    self.logger.info("%s -> %s : SYN DROPPED" % (ipo.src, ipo.dst))
                                    self.tcp_conn_track = self.track.conn_track_dict(self.tcp_conn_track, ipo.src, ipo.dst, tcpo.src_port,
                                                                                     tcpo.dst_port, tcpo.seq, 1)
                                    self.flow.add_flow(datapath=datapath, actions=actions_default, priority = 1002, in_port=in_port,
                                                       eth_type = ETH_TYPE_IP, ip_proto= IPPROTO_TCP,
                                                       ipv4_src = ipo.src, ipv4_dst=ipo.dst,
                                                       tcp_src=tcpo.src_port, tcp_dst=tcpo.dst_port)
                                    break 
                    # TCP SYN ACK packet  
                    elif (tcpo.bits & TCP_SYN_ACK) == TCP_SYN_ACK:
                        print("TCP_SYN_ACK!!")
                        if ipo.dst in self.tcp_conn_track:
                            temp2 = self.tcp_conn_track.get(ipo.dst)
                            for i in range(0, len(temp2)):
                                 # <here>
                                if (temp2[i][0] == ipo.src) and (int(temp2[i][1]) == tcpo.dst_port) and (int(temp2[i][2]) == tcpo.src_port):
                                    print("TCP SA track")
                                    flag2 = 1 
                                    actions_default = action_drop
                                    self.logger.info("%s -> %s : SYN ACK DROPPED" % (ipo.src, ipo.dst))
                                    self.tcp_conn_track = self.track.conn_track_dict(self.tcp_conn_track, ipo.src, ipo.dst, tcpo.src_port,
                                                                                     tcpo.dst_port, tcpo.seq, 1)
                                    self.flow.add_flow(datapath = datapath, actions=actions_default, priority = 1002, in_port = in_port,
                                                       eth_type = ETH_TYPE_IP, ip_proto = IPPROTO_TCP, ipv4_src = ipo.src,
                                                       ipv4_dst = ipo.dst, tcp_src=tcpo.src_port, tcp_dst=tcpo.dst_port)
                                    self.logger.info("\n %s -> %s src_port=%s, dst_port=%s, state= BLOCKED\n" %(ipo.dst, ipo.src, temp2[i][1], temp2[i][2]))
                                    break 
                    # All remaining TCP packets 
                    else:
                        if ipo.src in self.tcp_conn_track:
                            temp3 = self.tcp_conn_track.get(ipo.src)
                            for i in range(0, len(temp3)):
                                #  <here>
                                if (temp3[i][0] == ipo.dst) and (int(temp3[i][1]) == tcpo.src_port) and (int(temp3[i][2]) == tcpo.dst_port):
                                    flag2 = 1 
                                    actions_default = action_drop
                                    self.logger.info("%s -> %s : TRANSMISSION DROPPED" % (ipo.src, ipo.dst))
                                    break 
                    # No match 
                    if flag2 == 0:
                        actions_default = action_fwd_to_out_port
                        self.flow.add_flow(datapath=datapath, actions=actions_default, priority = 1001, in_port=in_port,
                                            eth_type = ETH_TYPE_IP, ip_proto= IPPROTO_TCP,
                                            ipv4_src = ipo.src, ipv4_dst=ipo.dst,
                                            tcp_src=tcpo.src_port, tcp_dst=tcpo.dst_port)
                        self.logger.info("%s -> %s : ALLOWED" % (ipo.src, ipo.dst))
                
                # Check for UDP 
                elif ipo.proto == IPPROTO_UDP:
                    flag3 = 0 
                    udpo = pkt.get_protocol(udp.udp)
                    # udp_payload = udpo.payload
                    # Check for tracked UDP 
                    if ipo.dst in self.udp_conn_track:
                        tmp_tpl = self.udp_conn_track.get(ipo.dst)
                        tmp = list(tmp_tpl)
                        for i in range(0, len(tmp)):
                            #  <here>
                            if(tmp[i][0] == ipo.src):
                                xyz = tmp[i]
                                # <here>
                                if (int(xyz[1]) == udpo.dst_port) and (int(xyz[2]) == udpo.src_port) and (xyz[3] == "UNREPLIED"):
                                    flag3 = 1 
                                    self.logger.info("%s -> %s : UDP PACKET ALLOWED" % (ipo.src, ipo.dst))
                                    actions_default = action_fwd_to_out_port
                                    del tmp[i]
                                    self.logger.info("\n%s -> %s src_port= %s, dst_port= %s, state= ASSURED\n" %(ipo.src, ipo.dst,
                                                                                                                 udpo.src_port, udpo.dst_port))
                                    self.flow.add_flow(datapath=datapath, actions=actions_default, priority=1001, in_port = in_port,
                                                       eth_type = ETH_TYPE_IP, ip_proto = IPPROTO_UDP, 
                                                       ipv4_src = ipo.src, ipv4_dst = ipo.dst, 
                                                       udp_src = udpo.src_port, udp_dst = udpo.dst_port)
                                    break 
                        tmp_tpl = tuple(tmp)
                        if len(tmp_tpl) != 0:
                            self.udp_conn_track[ipo.dst] = tmp_tpl
                        else:
                            self.udp_conn_track.pop(ipo.dst, None)
                    # Check for first UDP packet 
                    elif ipo.src in self.inner_policy:
                        temp = self.inner_policy.get(ipo.src)
                        for i in range(0, len(temp)):
                            #  <here>
                            if temp[i][0] == ipo.dst:
                                xyz = temp[i]
                                #  <here>
                                if (xyz[1] == 'UDP') and (int(xyz[2]) == udpo.src_port) and (int(xyz[3]) == udpo.dst_port) and (xyz[5] == 'ALLOW'): 
                                    flag3 = 1 
                                    actions_default = action_fwd_to_out_port
                                    self.udp_conn_track = self.track.conn_track_dict(self.udp_conn_track, ipo.src, ipo.dst, udpo.src_port, 
                                                                                     udpo.dst_port, "UNREPLIED", 1)
                                    self.logger.info("%s -> %s : UDP PACKET ALLOWED" % (ipo.src, ipo.dst))
                                    self.logger.info("\n%s -> %s src_port= %s, dst_port= %s, state= UNREPLIED\n" %(ipo.src, ipo.dst, udpo.src_port, udpo.dst_port))
                                    self.flow.add_flow(datapath = datapath, actions = actions_default, priority =  1001, in_port = in_port,
                                                       eth_type =ETH_TYPE_IP, ip_proto=IPPROTO_UDP,
                                                       ipv4_src = ipo.src, ipv4_dst = ipo.dst,
                                                       udp_src = udpo.src_port, udp_dst = udpo.dst_port)
                                    break 
                    # No match 
                    if flag3 == 0:
                        actions_default = action_drop
                        self.logger.info("%s -> %s : UDP BLOCKED" % (ipo.src, ipo.dst))
                        self.flow.add_flow(datapath = datapath, actions = actions_default, priority =  1002,
                                            in_port = in_port, eth_type =ETH_TYPE_IP, ip_proto=IPPROTO_UDP,
                                            ipv4_src = ipo.src, ipv4_dst = ipo.dst,
                                            udp_src = udpo.src_port, udp_dst = udpo.dst_port)

                # If not ICMP, TCP or UDP then drop!
                else:
                    self.logger.info("Wrong IP protoco found")
                    actions_default = action_drop
            # Handling ARP rules
            elif(ethtype == ETH_TYPE_ARP):
                self.arp_handling(datapath, out_port, eth, in_port)
                actions_default = action_fwd_to_out_port

            # If packet is not IP or ARP then drop!
            else:
                actions_default = action_drop

        except Exception as err:
            self.logger.info("ERROR in 425: %s", err)
            action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
            actions_default = action_drop
        finally:
            self.sendpkt.send(datapath, msg, in_port, actions_default)

    # Add ARP rules on Flow Tables 
    def arp_handling(self, datapath, out_port, eth_obj, in_port):
        if out_port != datapath.ofproto.OFPP_FLOOD:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.flow.add_flow(datapath=datapath, actions = actions, priority=1001,
                               in_port=in_port, eth_type=ETH_TYPE_ARP, eth_src=eth_obj.src,eth_dst=eth_obj.dst)

    def port_learn(self, datapath, eth_obj, in_port):
        try:
            self.mac_to_port.setdefault(datapath.id, {'00:00:00:00:00:01':1, '00:00:00:00:00:02':2, '00:00:00:00:00:03':3, '00:00:00:00:00:04':5,
                                                      '00:00:00:00:00:06':6,'00:00:00:00:00:07':7,'00:00:00:00:00:08':8,'00:00:00:00:00:09':9,
                                                      '00:00:00:00:00:10':10,'00:00:00:00:00:11':11,'00:00:00:00:00:12':12,'00:00:00:00:00:12':13,
                                                      '00:00:00:00:00:14':14,'00:00:00:00:00:15':15,})
            self.mac_to_port[datapath.id][eth_obj.src] = in_port

            if (eth_obj.ethertype == ETH_TYPE_IP) or (eth_obj.ethertype == ETH_TYPE_ARP):
                if eth_obj.dst in self.mac_to_port[datapath.id]:
                    out_port = self.mac_to_port[datapath.id][eth_obj.dst]
                    return out_port 
                out_port = datapath.ofproto.OFPP_FLOOD
                return out_port 
        except Exception as err:
            self.info("Error in 435: ",err)
            out_port = datapath.ofproto.OFPP_FLOOD
            return out_port
