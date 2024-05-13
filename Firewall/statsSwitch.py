from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
# import ryu.app.ofctl.api as api


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

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
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        # print("REQUEST STATS")
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        print("**************************************")
        print("**************************************")
        # self.getFlows(ev.msg.datapath)
        self.logger.info('datapath         '
                         'in-port  eth-dst       eth_src    '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority >= 1],
                           key=lambda flow: (flow.match.get('in_port', 0),
                                             flow.match.get('eth_dst', ''),
                                             flow.match.get('eth_src', ''))):
            self.logger.info('%016x %4x %17s %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'], stat.match['eth_src'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

        print("**************************************")
        print("**************************************")
			 #     body = ev.msg.body
			 #
			 #     self.logger.info('datapath         '
			 # 'actions                                             '
			 #                      'packets  bytes')
			 #     self.logger.info('---------------- '
			 #                      '--------------------------------------------------- '
			 #                      '-------- --------')
			 #     for stat in sorted([flow for flow in body if flow.priority >= 1],
			 #                        key=lambda flow: flow.instructions[0].actions[0].port):
			 #         self.logger.info('%016x %51s %8d %8d',
			 #                          ev.msg.datapath.id,stat.instructions[0].actions[0].port,
			 #                          stat.packet_count, stat.byte_count)
			 #         if(int(stat.byte_count) > 2000000):
			 #             #add a flow to slower hosts wire speed 
			 #             dp = ev.msg.datapath
			 #             ofp = dp.ofproto
			 #             parser = dp.ofproto_parser
			 #
			 #             match = parser.OFPMatch(in_port=stat.match['in_port'])
			 #             actions = [parser.OFPActionSetQueue(1)]
			 #             inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions),parser.OFPInstructionGotoTable(1)]
			 #             mod = parser.OFPFlowMod(datapath=dp, priority=1001,match=match, instructions=inst)
			 #             dp.send_msg(mod)
			 #         if(int(stat.byte_count) > 3000000):
			 #             #add a flow to drop the packet
			 #             dp = ev.msg.datapath
			 #             ofp = dp.ofproto
			 #             parser = dp.ofproto_parser
			 #
			 #             match = parser.OFPMatch(in_port=stat.match['in_port'])
			 #             actions = [parser.OFPActionSetQueue(2)]
			 #             inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions),parser.OFPInstructionGotoTable(1)]
			 #             mod = parser.OFPFlowMod(datapath=dp, priority=1002,match=match, instructions=inst)
			 #             dp.send_msg(mod)

    # def ofdpaTableStatsRequest(self, datapath):
    #     parser = datapath.ofproto_parser
    #     return parser.OFPTableStatsRequest(datapath)
    #
    # def getFlows(self, datapath):
    #     """
    #     Obtain a list of Flows loaded on the switch
    #     `
    #     :return: A list of Flow Entires
    #     """
    #     msg = self.ofdpaTableStatsRequest(datapath)
    #     reply = api.send_msg(ryuapp, msg,
    #                         reply_cls=self.parser.OFPTableStatsReply,
    #                         reply_multi=True)
    # @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    # def _port_stats_reply_handler(self, ev):
    #     body = ev.msg.body
    #
    #     self.logger.info('datapath         port     '
    #                      'rx-pkts  rx-bytes rx-error '
    #                      'tx-pkts  tx-bytes tx-error')
    #     self.logger.info('---------------- -------- '
    #                      '-------- -------- -------- '
    #                      '-------- -------- --------')
    #     for stat in sorted(body, key=attrgetter('port_no')):
    #         self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
    #                          ev.msg.datapath.id, stat.port_no,
    #                          stat.rx_packets, stat.rx_bytes, stat.rx_errors,
    #                          stat.tx_packets, stat.tx_bytes, stat.tx_errors)
