# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, udp
from ryu.lib.packet import ether_types


class MySimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MySimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6)
        self.add_flow(datapath, 10, match, actions)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17)
        self.add_flow(datapath, 10, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.logger.debug("ADD_FLOW --> DATAP: %s, MATCH: %s, AC: %s", datapath, 
                        match, actions)
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        
            

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        self.logger.debug("ACTION --> %s", actions)
        try:
            _ipv4 = pkt.get_protocol(ipv4.ipv4)
            
            src_addr = _ipv4.src
            dst_addr = _ipv4.dst

            self.logger.debug("IPV4_PROTO --> %s", _ipv4.proto)           
            if _ipv4.proto == 6:
                _tcp = pkt.get_protocol(tcp.tcp)
                src_port, dst_port = _tcp.src_port, _tcp.dst_port
                match = parser.OFPMatch(tcp_src=src_port, tcp_dst=dst_port,
                                        ipv4_src=src_addr, ipv4_dst=dst_addr,
                                        ip_proto=_ipv4.proto, eth_type=0x0800)
                self.logger.debug("MATCH %s", match)          
                
            elif _ipv4.proto == 17:
                _udp = pkt.get_protocol(udp.udp)
                src_port, dst_port = _udp.src_port, _udp.dst_port
                match = parser.OFPMatch(udp_src=src_port, udp_dst=dst_port,
                                        ipv4_src=src_addr, ipv4_dst=dst_addr,
                                        ip_proto=_ipv4.proto, eth_type=0x0800)
                self.logger.debug("MATCH %s", match)          

            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 20, match, actions, msg.buffer_id)
                self.logger.debug("DATAPATH, %s, MATCH, %s, ACTION, %s, BUFFERID, %s ", 
                                datapath, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 20, match, actions)
                self.logger.debug("DATAPATH, %s, MATCH, %s, ACTION, %s", 
                                datapath, match, actions)

        except:
            self.logger.debug("Protocol --> %s", eth)
 
        # install a flow to avoid packet_in next time
    
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                self.logger.debug("DATAPATH, %s, MATCH, %s, ACTION, %s, BUFFERID, %s ", 
                                datapath, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
                self.logger.debug("DATAPATH, %s, MATCH, %s, ACTION, %s", 
                                datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
