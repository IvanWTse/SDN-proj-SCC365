# -*- coding: utf-8 -*-

"""
Ryu Layer 2 Learning Switch

Note: Requires Python3.8 or higher (uses the ':=' operator)
"""
import json

# import ryu.controller.controller
import time

import ryu
from ryu.app.ofctl.api import get_datapath
from ryu.app.wsgi import ControllerBase, route, Response, WSGIApplication
from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event, dpset
from ryu.controller.controller import Datapath
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.ipv6 import ipv6
from ryu.lib.packet.lldp import lldp
from ryu.lib.dpid import dpid_to_str, DPID_PATTERN, str_to_dpid
from ryu.lib.packet import ipv4


class Controller(RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication, 'dpset': dpset.DPSet}

    ILLEGAL_PROTOCOLS = [ipv6, lldp]

    def __init__(self, *args, **kwargs):
        '''
        Init | Constructor
        '''
        super(Controller, self).__init__(*args, **kwargs)
        self.mac_port_map = {}
        jsonText = "".join(open("vports.json").readlines())
        self.vPortMap = json.loads(jsonText)
        self.dpPorts = {}
        self.vp_groupid = {}
        wsgi = kwargs['wsgi']
        wsgi.register(ControllerAPI, {"myController": self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        '''
        Handshake: Features Request Response Handler
        '''
        datapath: ryu.controller.controller.Datapath = ev.msg.datapath
        match = datapath.ofproto_parser.OFPMatch()
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                                           datapath.ofproto.OFPCML_NO_BUFFER)]
        datapath.send_msg(datapath.ofproto_parser.OFPPortDescStatsRequest(datapath, 0))
        self.send_group_mod(datapath)
        self.mac_port_map[dpid_to_str(datapath.id)] = {}
        self.__add_flow(datapath, 0, match, actions, idle=0)
        self.logger.info("🤝\thandshake taken place with datapath: {}".format(dpid_to_str(datapath.id)))

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        '''
        OpenFlow Error Handler
        '''
        error = ev.msg.datapath.ofproto.ofp_error_to_jsondict(ev.msg.type, ev.msg.code)
        # self.logger.error(
        #     "🆘\topenflow error received:\n\t\ttype={}\n\t\tcode={}".format(error.get("type"), error.get("code")))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Packet In Event Handler
        '''
        datapath = ev.msg.datapath
        self.logger.debug("❗️\tevent 'packet in' from datapath: {}".format(dpid_to_str(datapath.id)))
        pkt = packet.Packet(ev.msg.data)
        in_port = ev.msg.match['in_port']
        if self.__illegal_packet(pkt):
            return

        # Set defaults
        # actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        actions = []

        # Only perform layer 2 learning if packet has an ethernet header
        if eth_header := pkt.get_protocol(ethernet):
            dpid = dpid_to_str(datapath.id)
            vPortDict = self.vPortMap[dpid]
            # for vpName, vPorts in vPortDict.items():
            #     if in_port in vPorts:
            #         actions = [datapath.ofproto_parser.OFPActionGroup(self.vp_groupid.get(dpid + vpName))]
            #         match = datapath.ofproto_parser.OFPMatch(eth_dst=eth_header.src)
            #         self.__add_flow(datapath, 2, match, actions)
            #         break

            # add/update the layer 2 information to the controller's global map
            print("a packet in: inPort: " + str(in_port) + " src: " + str(eth_header.src))
            if not self.mac_port_map[dpid].get(eth_header.src, None):
                self.mac_port_map[dpid][eth_header.src] = in_port
                actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                match = datapath.ofproto_parser.OFPMatch(eth_dst=eth_header.src)
                self.__add_flow(datapath, 1, match, actions)

            # L2L learning part
            for port in self.__floodPkt(datapath, dpid_to_str(datapath.id), in_port):
                actions.append(datapath.ofproto_parser.OFPActionOutput(port))
            # (here it could be also added to the flow table...)

            # check if current packet has known egress port
            # if port := self.mac_port_map.get(dpid_to_str(datapath.id), {}).get(eth_header.dst, None):
            #     # set output port to be known port, overwriting the FLOOD directive
            #     actions = [datapath.ofproto_parser.OFPActionOutput(port)]
            #     # install this logic to the datapath's flow table
            #     match = datapath.ofproto_parser.OFPMatch(eth_dst=eth_header.dst)
            #     print("action port: " + str(port))
            #     print("ethDest: " + str(eth_header.dst))
            #     self.__add_flow(datapath, 1, match, actions)

        # Send the packet out
        pkt_out_msg = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ev.msg.buffer_id,
                                                           in_port=in_port, actions=actions, data=ev.msg.data)
        datapath.send_msg(pkt_out_msg)
        return

    def __floodPkt(self, datapath: Datapath, dpid: str, in_port: int):
        if dpid not in self.vPortMap:
            return [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        excludeVportName = None
        excludePorts = None
        vPortList = self.vPortMap[dpid].copy()

        # Query the ports of the datapath
        ports = self.dpPorts[dpid].copy()

        # Find if data is from a vport and exclude it if true
        for vpName, vPorts in vPortList.items():
            if in_port in vPorts:
                excludeVportName = vpName
                excludePorts = vPorts
                break

        # Filter incoming vports if exists
        if excludeVportName:
            outputPorts = [port for port in ports if port not in excludePorts]
        else:
            outputPorts = ports.copy()

        # Exclude duplicate port in vports
        for vports in vPortList.values():
            if vports == excludePorts:
                continue
            for vport in vports:
                if vport in outputPorts:
                    for _ in vports:
                        outputPorts.remove(_)
                    outputPorts.append(vport)
        # Exclude the incoming port itself
        if in_port in outputPorts:
            outputPorts.remove(in_port)
        print("floodPkt: " + str(outputPorts) + " from: " + dpid)
        return outputPorts

    def send_group_mod(self, datapath: Datapath):
        dpid = dpid_to_str(datapath.id)
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        if dpid not in self.vPortMap:
            self.logger.error("datapath " + datapath.id + "not in vPortsMap")
            return

        __vportsDict = self.vPortMap[dpid]
        groupidCounter = 0
        # Traverse vport sets
        for _vportName, _vports in __vportsDict.items():
            groupId = groupidCounter
            # Maintain the group id
            self.vp_groupid[dpid + _vportName] = groupId
            groupidCounter += 1
            buckets = []
            # Traverse each port
            for _port in _vports:
                action = [ofp_parser.OFPActionOutput(_port)]
                # Put the action into a bucket
                buckets.append(ofp_parser.OFPBucket(50, ofproto_v1_3.OFPP_ANY, ofproto_v1_3.OFPQ_ALL, action))
            # Put the bucket into data plane
            req = ofp_parser.OFPGroupMod(datapath, ofproto.OFPFC_ADD, ofproto.OFPGT_SELECT, groupId, buckets)
            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, CONFIG_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        ports = []
        for p in ev.msg.body:
            ports.append(p.port_no)

        ports = filter(lambda x: x < 1000, ports)
        self.dpPorts[dpid_to_str(ev.msg.datapath.id)] = list(ports)

    def __illegal_packet(self, pkt, log=True):
        '''
        Illegal Packet Check
        '''
        for proto in self.ILLEGAL_PROTOCOLS:
            if pkt.get_protocol(proto) and log:
                if log:
                    # self.logger.debug("🚨\tpacket with illegal protocol seen: {}".format(proto.__name__))
                    pass
                return True
        return False

    def __add_flow(self, datapath, priority, match, actions, idle=60, hard=0):
        '''
        Install Flow Table Modification
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle,
                                hard_timeout=hard)
        self.logger.info("✍️\tflow-Mod written to datapath: {}, match:{}, actions:{}".format(dpid_to_str(datapath.id), str(match), str(actions)))
        datapath.send_msg(mod)


class ControllerAPI(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(ControllerAPI, self).__init__(req, link, data, **config)
        self.loadPortsStats = None
        self.controller = data.get("myController")
        self.vports = self.controller.vPortMap

    @route('controller_info', "/api/info", methods=['GET'])
    def get_controller_info(self, req, **kwargs):
        body = json.dumps({
            "class": self.controller.__class__.__name__,
            "functions": [function for function in dir(self.controller) if callable(getattr(self.controller, function))]
        })
        return Response(status=200, content_type='application/json', charset='UTF-8', body=body)

    @route('controller_datapaths', "/api/datapaths", methods=['GET'])
    def get_controller_datapaths(self, req, **kwargs):
        body = json.dumps(list(self.controller.mac_port_map.keys()))
        return Response(status=200, content_type='application/json', charset='UTF-8', body=body)

    @route('controller_mappings', "/api/mappings", methods=['GET'])
    def get_controller_mappings(self, req, **kwargs):
        body = json.dumps(dict(self.controller.mac_port_map))
        return Response(status=200, content_type='application/json', charset='UTF-8', body=body)

    @route('controller_datapath_mappings', "/api/mappings/{dpid}", methods=['GET'],
           requirements={'dpid': DPID_PATTERN})
    def get_controller_datapath_mappings(self, req, **kwargs):
        if not kwargs['dpid'] in self.controller.mac_port_map.keys():
            error_body = json.dumps({
                "error": "your datapath id " + str(kwargs['dpid']) + " not in mappings table",
                "availableDatapaths": list(self.controller.mac_port_map.keys())
            })
            return Response(status=400, content_type='application/json', charset='UTF-8', body=error_body)
        body = json.dumps(dict(self.controller.mac_port_map.get(kwargs['dpid'])))
        return Response(status=200, content_type='application/json', charset='UTF-8', body=body)

    # Added
    @route('virtual_ports', "/api/virtualports", methods=['GET'])
    def get_virtual_ports(self, req, **kwargs):
        v_ports = json.dumps(self.vports)

        return Response(status=200, content_type='application/json', charset='UTF-8', body=v_ports)

    @route('datapath_virtual_ports', "/api/virtualports/{dpid}", methods=['GET'],
           requirements={'dpid': DPID_PATTERN})
    def get_datapath_virual_ports(self, req, **kwargs):
        if not kwargs['dpid'] in self.controller.mac_port_map.keys():
            error_body = json.dumps({
                "error": "your datapath id " + str(kwargs['dpid']) + " not in mappings table",
                "availableDatapaths": list(self.controller.mac_port_map.keys())
            })
            return Response(status=400, content_type='application/json', charset='UTF-8', body=error_body)
        body = json.dumps(self.vports[kwargs['dpid']])
        return Response(status=200, content_type='application/json', charset='UTF-8', body=body)
