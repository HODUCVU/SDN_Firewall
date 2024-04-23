import logging
from ryu.ofproto.ether import ETH_TYPE_LLDP
from construct_flow import Construct 

class ResetSwitch():
    # Reset the switch. Flush all flow table entries and set up default behavior

    def __init__(self, dp):
        self.__rest_switch(dp)

    def __rest_switch(self, dp):
        assert (dp is not None), "Datapath Object is not set."

        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        flow_mod = dp.ofproto_parser.OFPFlowMod(dp, 0,0,0,
                                                ofproto.OFPFC_DELETE, 0,0,1,
                                                ofproto.OFPCML_NO_BUFFER,
                                                ofproto.OFPP_ANY,
                                                ofproto.OFPG_ANY)
        logging.info("Deleting all flow table entries...")
        dp.send_msg(flow_mod)

        # Install table-miss flow entry
        const = Construct()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        const.add_flow(datapath=dp, actions=actions, priority=0)

        actions = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
        const.add_flow(datapath = dp, actions=actions, priority=1000k, eth_type = ETH_TYPE_LLDP)
