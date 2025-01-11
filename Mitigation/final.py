from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix, accuracy_score

class SimpleMonitor13(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        
        start = datetime.now()
        self.flow_training()  # Start training on initialization
        end = datetime.now()
        print("Training Accuracy: {:.2f}%".format(self.train_accuracy * 100))
        print("Training time: ", (end - start))

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

    def flow_training(self):
        self.logger.info("Flow Training ...")
        try:
            flow_dataset = pd.read_csv('dataset.csv')
            if flow_dataset.empty:
                self.logger.error("Dataset is empty!")
                return

            flow_dataset = flow_dataset.sample(frac=0.1, random_state=0)
            flow_dataset = flow_dataset.replace('.', '', regex=True).fillna(0)
            flow_dataset = flow_dataset.apply(pd.to_numeric, errors='coerce').fillna(0)

            X_flow = flow_dataset.iloc[:, :10].values.astype('float64')
            y_flow = flow_dataset.iloc[:, -1].values

            X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

            classifier = KNeighborsClassifier(n_neighbors=5, metric='minkowski', p=2)
            self.flow_model = classifier.fit(X_flow_train, y_flow_train)
            y_flow_pred = self.flow_model.predict(X_flow_test)
            cm = confusion_matrix(y_flow_test, y_flow_pred)
            self.train_accuracy = accuracy_score(y_flow_test, y_flow_pred)

            self.logger.info("Confusion Matrix")
            self.logger.info(cm)
            self.logger.info("Success Accuracy = {:.2f}%".format(self.train_accuracy * 100))
            self.logger.info("Fail Accuracy = {:.2f}%".format((1.0 - self.train_accuracy) * 100))

        except Exception as e:
            self.logger.error(f"Error in flow_training: {e}")

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

           # if predict_flow_dataset.empty:
            ##    self.logger.error("Prediction dataset is empty!")
             #   return

            #predict_flow_dataset = predict_flow_dataset.replace('.', '', regex=True).fillna(0)
           # predict_flow_dataset = predict_flow_dataset.apply(pd.to_numeric, errors='coerce').fillna(0)

           # if predict_flow_dataset.shape[0] == 0:
           #     self.logger.error("No valid data for prediction!")
            #    return

            X_predict_flow = predict_flow_dataset.iloc[:, :10].values.astype('float64')
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_traffic = sum(y == 0 for y in y_flow_pred)
            ddos_traffic = sum(y == 1 for y in y_flow_pred)

            if legitimate_traffic / len(y_flow_pred) > 0.8:
                self.logger.info("Traffic is Legitimate!")
            else:
                self.logger.info("NOTICE!! DoS Attack in Progress!!!")
                victim = "Unknown"
                if ddos_traffic > 0:
                    victim = int(predict_flow_dataset.iloc[ddos_traffic - 1, 5]) % 20
                self.logger.info(f"Victim Host: h{victim}")
                print("Mitigation process in progress!")
                self.mitigation = 1

            with open("PredictFlowStatsfile.csv", "w") as file:
                file.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
                           'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,'
                           'byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,'
                           'byte_count_per_nsecond\n')

        except Exception as e:
            self.logger.error(f"Error in flow_predict: {e}")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        with open("PredictFlowStatsfile.csv", "w") as file0:
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
                        'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,'
                        'byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,'
                        'byte_count_per_nsecond\n')
            timestamp = datetime.now().timestamp()

            for stat in ev.msg.body:
                ip_src = stat.match.get('ipv4_src', None)
                ip_dst = stat.match.get('ipv4_dst', None)
                tp_src = stat.match.get('tp_src', 0)
                tp_dst = stat.match.get('tp_dst', 0)

                if ip_src is None or ip_dst is None:
                    self.logger.debug("Non-IP flow entry encountered, skipping.")
                    continue

                row = [
                    timestamp, ev.msg.datapath.id, f"{ip_src}-{ip_dst}",
                    ip_src, tp_src,
                    ip_dst, tp_dst,
                    stat.match.get('ip_proto', 0), stat.match.get('icmpv4_code', -1),
                    stat.match.get('icmpv4_type', -1), stat.duration_sec, stat.duration_nsec,
                    stat.idle_timeout, stat.hard_timeout, stat.flags,
                    stat.packet_count, stat.byte_count,
                    stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0,
                    stat.packet_count / stat.duration_nsec if stat.duration_nsec > 0 else 0,
                    stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0,
                    stat.byte_count / stat.duration_nsec if stat.duration_nsec > 0 else 0
                ]
                file0.write(','.join(map(str, row)) + "\n")

