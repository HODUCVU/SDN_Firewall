from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
# from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_0, ofproto_v1_2, ofproto_v1_3
from ryu.ofproto import ofproto_v1_0_parser, ofproto_v1_2_parser, ofproto_v1_3_parser
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

# start_time = time.time()

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

    # insert_drop = {}
    total_packet = defaultdict(int)
    # last_time = time.monotonic() 
    # current_time = time.monotonic()

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
        # parser = ParseFirewallFromDB("dataset/firewall-drop.db")
        # self.inner_policy = parser.parse()
        self.inner_policy = self.database.parse()

        self.totaltime = 0.0
        # self.current_time = time.time()
        self.last_time = time.time() 
        self.monitor_thread = hub.spawn(self._monitor)

        if self.inner_policy:
            self.logger.info("Firewall rules parsed successfully from the database.")
        else:
            self.logger.error("Failed to parse firewall rules from the database.")
        self.logger.info("dict is ready")

    def _monitor(self):
        while True:
            current_time = time.time()
            elapsed_time = current_time - self.last_time
            self.totaltime += elapsed_time
            print("on monitor: ", self.totaltime)
            self.last_time = current_time
            hub.sleep(1)
        # self.current_time = time.time()
        # self.totaltime = round((self.current_time - self.last_time), 1)
        # hub.sleep(1)


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
        # out_port = ofproto.OFPP_FLOOD 

        try:
            pkt = packet.Packet(msg.data)
            # data = pkt.data
            # print("len: ", len(data)," - data: ", data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            ethtype = eth.ethertype

            out_port = self.port_learn(datapath, eth, in_port)
            action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]

            # if out_port != ofproto.OFPP_FLOOD:
            action_fwd_to_out_port = [parser.OFPActionOutput(out_port)]
            # else:
                # action_fwd_to_out_port = action_drop 
            actions_default = action_fwd_to_out_port

            if(out_port != ofproto.OFPP_FLOOD) and (ethtype == ETH_TYPE_IP):
                # <here>
                ipo = pkt.get_protocols(ipv4.ipv4)[0]
                # <check behave>
                # <add extract header for this condition>
                if(ipo.src not in self.inner_policy) or (ipo.dst not in self.inner_policy):
                    self.total_packet[(ipo.src, ipo.dst)] += 1

                print("totaltile: ", self.totaltime)
                if(self.totaltime >= 1.0):
                        # firewall_rules = [
                        #     ("10.0.0.3", "10.0.0.4", "ICMP", None, None, "PING", "DROP"),
                        #     ("10.0.0.1", "10.0.0.2", "TCP", 1000, 8080, "NEW", "ALLOW"),
                        #     ]
                    self.totaltime = 0.0
                    print("------")
                    print("total packet from %s -> %s: " % (ipo.src, ipo.dst), self.total_packet[(ipo.src, ipo.dst)] )
                    print("------")
                    if self.total_packet[(ipo.src, ipo.dst)] >= 10:
                        self.total_packet[(ipo.src, ipo.dst)] = 1

                        # self.total_packet.clear()
                        #drop
                        if ipo.proto == IPPROTO_ICMP:
                            actions_default = action_drop #drop
                            self.icmp_conn_track = self.track.conn_track_dict(self.icmp_conn_track,ipo.src, ipo.dst, "PING", "PONG", xyz[5],1)
                            self.logger.info("%s -> %s: Oversend Package" % (ipo.src, ipo.dst))
                            self.flow.add_flow(datapath=datapath, actions=actions_default, priority=1002, in_port=in_port,
                                                eth_type=ETH_TYPE_IP, ip_proto=IPPROTO_ICMP, icmpv4_type=ICMP_PING, 
                                                ipv4_src=ipo.src, ipv4_dst = ipo.dst)
                        elif ipo.proto == IPPROTO_TCP:
                            tcpo = pkt.get_protocol(tcp.tcp)
                            actions_default = action_drop
                            self.logger.info("%s -> %s : Oversend TCP Package" % (ipo.src, ipo.dst))
                            self.tcp_conn_track = self.track.conn_track_dict(self.tcp_conn_track, ipo.src, ipo.dst, tcpo.src_port,
                                                                                tcpo.dst_port, tcpo.seq, 1)
                            self.flow.add_flow(datapath=datapath, actions=actions_default, priority = 1002, in_port=in_port,
                                                eth_type = ETH_TYPE_IP, ip_proto= IPPROTO_TCP,
                                                ipv4_src = ipo.src, ipv4_dst=ipo.dst,
                                                tcp_src=tcpo.src_port, tcp_dst=tcpo.dst_port)
                    # self.last_time = self.current_time
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
                                    self.flow.add_flow(datapath=datapath, actions=actions_default, priority=1001, in_port=in_port,
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
                                                       priority=1001, in_port=in_port, eth_type=ETH_TYPE_IP,
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
                        self.flow.add_flow(datapath=datapath, actions=actions_default, priority=1001,
                                           in_port=in_port, eth_type=ETH_TYPE_IP, ip_proto = IPPROTO_ICMP,
                                           icmpv4_type = icmpob.type, ipv4_src = ipo.src, ipv4_dst = ipo.dst)
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
                                    self.flow.add_flow(datapath=datapath, actions=actions_default, priority = 1001, in_port=in_port,
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
                                    self.flow.add_flow(datapath = datapath, actions=actions_default, priority = 1001, in_port = in_port,
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
                        self.flow.add_flow(datapath = datapath, actions = actions_default, priority =  1001,
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
            self.logger.info("ERROR: %s", err)
            action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
            actions_default = action_drop
        finally:
            self.sendpkt.send(datapath, msg, in_port, actions_default)

    # Add ARP rules on Flow Tables 
    def arp_handling(self, datapath, out_port, eth_obj, in_port):
        if out_port != datapath.ofproto.OFPP_FLOOD:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.flow.add_flow(datapath=datapath, actions = actions, priority=1000,
                               in_port=in_port, eth_type=ETH_TYPE_ARP, eth_src=eth_obj.src,eth_dst=eth_obj.dst)

    def port_learn(self, datapath, eth_obj, in_port):
        try:
            self.mac_to_port.setdefault(datapath.id, {'00:00:00:00:00:01':1, '00:00:00:00:00:02':2, '00:00:00:00:00:03':3, '00:00:00:00:00:04':5,
                                                      '00:00:00:00:00:06':6,'00:00:00:00:00:07':7,'00:00:00:00:00:08':8,'00:00:00:00:00:09':9,
                                                      '00:00:00:00:00:10':10,'00:00:00:00:00:11':11,'00:00:00:00:00:12':12,'00:00:00:00:00:12':13,
                                                      '00:00:00:00:00:14':14,'00:00:00:00:00:15':15,})
            self.mac_to_port[datapath.id][eth_obj.src] = in_port
            # out_port = datapath.ofproto.OFPP_FLOOD

            if (eth_obj.ethertype == ETH_TYPE_IP) or (eth_obj.ethertype == ETH_TYPE_ARP):
                if eth_obj.dst in self.mac_to_port[datapath.id]:
                    out_port = self.mac_to_port[datapath.id][eth_obj.dst]
                    return out_port 
                # else:
                out_port = datapath.ofproto.OFPP_FLOOD
                return out_port 
        except Exception as err:
            self.info(err)
            out_port = datapath.ofproto.OFPP_FLOOD
            return out_port
        # finally:
        #     return out_port 
