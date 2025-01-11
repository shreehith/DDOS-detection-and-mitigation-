from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import os
import time

class DDoSMitigation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSMitigation, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.blocked_ips = set()
        self.blocked_ips_last_modified = None
        self.monitor_thread = hub.spawn(self._monitor_blocked_ips)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Registered datapath: %016x", datapath.id)

    def _monitor_blocked_ips(self):
        while True:
            self._check_blocked_ips_file()
            time.sleep(2)  # Reduce sleep time to make the check faster

    def _check_blocked_ips_file(self):
        try:
            # Check if the file has been modified since the last read
            file_path = "blocked_ips.txt"
            last_modified = os.path.getmtime(file_path)
            if self.blocked_ips_last_modified == last_modified:
                return  # File hasn't changed, skip processing

            # Update modification time and read new IPs
            self.blocked_ips_last_modified = last_modified
            with open(file_path, "r") as file:
                current_blocked_ips = set(file.read().splitlines())

            # Find IPs that are newly added to the blocked list
            new_ips_to_block = current_blocked_ips - self.blocked_ips
            for ip in new_ips_to_block:
                self._block_ip(ip)
                self.blocked_ips.add(ip)

        except FileNotFoundError:
            self.logger.error("blocked_ips.txt not found!")

    def _block_ip(self, ip):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            # Define match criteria for IPv4 source
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            actions = []  # Empty actions list will drop packets
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            # Send a flow mod message to add the block rule
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=200,  # High priority to override other flows
                match=match,
                instructions=instructions,
                command=ofproto.OFPFC_ADD,
                buffer_id=ofproto.OFP_NO_BUFFER,
                hard_timeout=0,
                idle_timeout=0,
                flags=ofproto.OFPFF_SEND_FLOW_REM
            )
            datapath.send_msg(mod)
            self.logger.info("Blocked IP: %s on datapath %s", ip, datapath.id)

