from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import switchm
from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix, accuracy_score
import ipaddress  # For IP validation
import os  # To check file existence

class SimpleMonitor13(switchm.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.mitigation_thread = hub.spawn(self._mitigation_monitor)

        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        print("Training time: ", (end - start))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('Send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        with open("PredictFlowStatsfile.csv", "w") as file0:
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            body = ev.msg.body

            for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
                ip_src = stat.match['ipv4_src']
                ip_dst = stat.match['ipv4_dst']
                ip_proto = stat.match['ip_proto']
                tp_src = stat.match.get('tcp_src', 0)
                tp_dst = stat.match.get('tcp_dst', 0)
                flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

                packet_count_per_second = stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0
                byte_count_per_second = stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0

                file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                    timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                    ip_proto, -1, -1, stat.duration_sec, stat.duration_nsec, stat.idle_timeout, stat.hard_timeout,
                    stat.flags, stat.packet_count, stat.byte_count, packet_count_per_second, 0, byte_count_per_second, 0))

    def flow_training(self):
        self.logger.info("Flow Training ...")
        # Load and prepare dataset without replacing dots in IP addresses
        flow_dataset = pd.read_csv('dataset.csv')

        # Exclude non-numeric columns (like IP addresses) for training
        # Assuming the IP-related columns are 'ip_src' and 'ip_dst', which are not used in the model
        # Update column names based on your dataset if needed
        X_flow = flow_dataset.select_dtypes(include=[float, int]).iloc[:, :-1].values
        y_flow = flow_dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)
        classifier = KNeighborsClassifier(n_neighbors=5, metric="minkowski", p=2)
        self.flow_model = classifier.fit(X_flow_train, y_flow_train)

        y_flow_pred = self.flow_model.predict(X_flow_test)
        cm = confusion_matrix(y_flow_test, y_flow_pred)
        acc = accuracy_score(y_flow_test, y_flow_pred)

        self.logger.info("Confusion Matrix:\n{}".format(cm))
        self.logger.info("Success accuracy = {:.2f} %".format(acc * 100))
        self.logger.info("Fail accuracy = {:.2f} %".format((1.0 - acc) * 100))

    def flow_predict(self):
        self.logger.info("Flow Prediction ...")
        # Add logic for flow prediction, which should handle cases when the model is not yet trained
        try:
            # Make sure prediction logic is updated based on correct feature extraction
            pass
        except Exception as e:
            self.logger.error(f"Error in flow prediction: {e}")

    def _mitigation_monitor(self):
        self.logger.info("Starting mitigation monitor...")
        blocked_ips = set()
        while True:
            try:
                if os.path.exists("blocked_ips.txt"):
                    with open("blocked_ips.txt", "r") as f:
                        ips = {line.strip() for line in f.readlines() if line.strip()}
                    new_ips = ips - blocked_ips
                    if new_ips:
                        for ip in new_ips:
                            try:
                                # Validate IP format
                                ipaddress.ip_address(ip)
                                self.logger.info("Attempting to block IP: {}".format(ip))
                                self._block_ip(ip)
                                blocked_ips.add(ip)
                            except ValueError:
                                self.logger.warning(f"Invalid IP address detected and ignored: {ip}")
                    else:
                        self.logger.info("No new IPs to block.")
                else:
                    self.logger.info("blocked_ips.txt not found, waiting for entries...")
            except Exception as e:
                self.logger.error(f"Error reading blocked_ips.txt: {e}")
            hub.sleep(10)

    def _block_ip(self, ip):
        self.logger.info("Applying block for IP: {}".format(ip))
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            match = parser.OFPMatch(ipv4_src=ip)
            actions = []  # No actions mean drop the packets
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst)
            dp.send_msg(mod)
            self.logger.info(f"Block rule for IP {ip} sent to datapath {dp.id}")

