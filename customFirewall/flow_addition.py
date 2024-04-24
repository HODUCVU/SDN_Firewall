import logging

class FlowAdd():
    # default function for construcing instructions.
    # Sends constructed message to connected Sswitch.

    def __init__(self):
        logging.info("Flow table rules are sent to switch")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=1800):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        modify = parser.OFPFlowMod(datapath=datapath, priority = priority, match=match,
                                   instructions = inst, idle_timeout = idle_timeout)

        datapath.send_msg(modify)
