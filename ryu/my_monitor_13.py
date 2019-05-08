# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#from operator import attrgetter
from ryu.base import app_manager
#from ryu.app import my_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import pandas as pd
import numpy as np


class MySimpleMonitor13(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(MySimpleMonitor13, self).__init__(*args, **kwargs)
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
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

 
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        data = pd.DataFrame({"datapath":[], "ip_proto":[], "port_src":[],
                             "port_dst":[], "action":[], "pkg_count":[], "byte_count":[]})

        for flow in body:
            if flow.priority == 20: 
                if flow.match['ip_proto'] == 6:
                    data = data.append({"datapath":[ev.msg.datapath.id], "ip_proto":[flow.match['ip_proto']], 
                               "port_src":[flow.match['tcp_src']], "port_dst":[flow.match['tcp_dst']],
                               "action":[flow.instructions[0].actions[0].port], "pkg_count":[flow.packet_count],
                               "byte_count":[flow.byte_count]}, ignore_index=True)
                elif flow.match['ip_proto'] == 17:
                    data = data.append({"datapath":[ev.msg.datapath.id], "ip_proto":[flow.match['ip_proto']], 
                               "port_src":[flow.match['udp_src']], "port_dst":[flow.match['udp_dst']],
                               "action":[flow.instructions[0].actions[0].port], "pkg_count":[flow.packet_count],
                               "byte_count":[flow.byte_count]}, ignore_index=True)
        self.logger.info(data)        
        
        
