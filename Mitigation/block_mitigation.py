from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score

class SimpleMonitor13(app_manager.RyuApp):
    
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        print("Training time: ", (end-start))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
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
            hub.sleep(10)
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        with open("PredictFlowStatsfile.csv", "w") as file0:
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            for stat in sorted([flow for flow in ev.msg.body if flow.priority == 1],
                               key=lambda flow: (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
                
                ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                ip_proto = stat.match.get('ip_proto', 0)
                icmp_code, icmp_type, tp_src, tp_dst = -1, -1, 0, 0

                if ip_proto == 1:
                    icmp_code = stat.match.get('icmpv4_code', -1)
                    icmp_type = stat.match.get('icmpv4_type', -1)
                elif ip_proto == 6:
                    tp_src = stat.match.get('tcp_src', 0)
                    tp_dst = stat.match.get('tcp_dst', 0)
                elif ip_proto == 17:
                    tp_src = stat.match.get('udp_src', 0)
                    tp_dst = stat.match.get('udp_dst', 0)

                flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

                packet_count_per_second = stat.packet_count / stat.duration_sec if stat.duration_sec else 0
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec if stat.duration_nsec else 0
                byte_count_per_second = stat.byte_count / stat.duration_sec if stat.duration_sec else 0
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec if stat.duration_nsec else 0
                
                file0.write(f"{timestamp},{ev.msg.datapath.id},{flow_id},{ip_src},{tp_src},{ip_dst},{tp_dst},{ip_proto},{icmp_code},{icmp_type},{stat.duration_sec},{stat.duration_nsec},{stat.idle_timeout},{stat.hard_timeout},{stat.flags},{stat.packet_count},{stat.byte_count},{packet_count_per_second},{packet_count_per_nsecond},{byte_count_per_second},{byte_count_per_nsecond}\n")

    def flow_training(self):
        self.logger.info("Flow Training ...")
        flow_dataset = pd.read_csv('dataset.csv')
        flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
        flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
        flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

        X_flow = flow_dataset.iloc[:, :-1].values.astype('float64')
        y_flow = flow_dataset.iloc[:, -1].values
        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

        self.flow_model = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0).fit(X_flow_train, y_flow_train)
        y_flow_pred = self.flow_model.predict(X_flow_test)

        cm = confusion_matrix(y_flow_test, y_flow_pred)
        acc = accuracy_score(y_flow_test, y_flow_pred)

        self.logger.info("Confusion Matrix:\n%s", cm)
        self.logger.info("Accuracy: {:.2f}%".format(acc * 100))

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')
            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

            X_predict_flow = predict_flow_dataset.values.astype('float64')
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_traffic = sum(1 for i in y_flow_pred if i == 0)
            ddos_traffic = sum(1 for i in y_flow_pred if i == 1)

            self.logger.info("------------------------------------------------------------------------------")
            if (legitimate_traffic / len(y_flow_pred) * 100) > 80:
                self.logger.info("Traffic detected is legitimate")
            else:
                self.logger.info("Alert! DDoS detected")
                victim = int(predict_flow_dataset.iloc[ddos_traffic, 5]) % 20
                self.logger.info("Victim is host: h{}".format(victim))
                self.logger.info("Mitigation in process")

            self.logger.info("------------------------------------------------------------------------------")
            with open("PredictFlowStatsfile.csv", "w") as file0:
                file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
        except Exception as e:
            self.logger.error("Prediction error: %s", str(e))

