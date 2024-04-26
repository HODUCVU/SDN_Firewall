import logging
from reset_flow_table import ResetSwitch

class SwitchInfo():
    # Handles switch connection and disconnection information.
    def __init__(self, event):
        switch = event.dp 
        if event.enter:
            logging.info("datapath has joined")
            logging.info(switch.ofproto)
            logging.info(switch.ofproto_parser)
            self.__switch_connected(switch)
        else:
            self.__switch_disconnected(switch)

    def __switch_connected(self, sw):
        logging.info("Switch %s has connected with OFP %s...", sw.id, sw.ofproto)
        ResetSwitch(sw)

    def __switch_disconnected(self, sw):
        logging.info("Switch %s has disconnected from OFP %s...", sw.id, sw.ofproto)
