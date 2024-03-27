import argparse
import json
import re
import sys

"""
VPort Automatic Generator

Automatically genereate content for `vports.json` files as expected when
developing the ECMP switch controller.

Note: Only working on redundant links where both endpoints are switches
"""


class VPortGenerator():

    VPORT_NAME_TEMPLATE = "VP{}"

    def __init__(self, topo):
        self.topo = topo()
        self.switches = self.__discover_switches()

    def generate(self):
        data = self.__create_empty()
        for s, dpid in self.switches.items():
            for n in self.topo.g.nodes(data=False):
                if ports := self.__get_ports(s, n):
                    data[dpid][self.__create_vport_name(len(data.get(dpid).keys())+1)] = ports
        return data

    def __create_empty(self):
        vports = {}
        for dpid in self.switches.values():
            vports[dpid] = {}
        return vports

    def __get_ports(self, switch, dst):
        '''
        Get Ports

        Get all the ports on a given switch that directly link to the same
        destination.
        '''
        ports = []
        for link in self.topo.g.edges(data=True, keys=False):
            if link[0] == switch and link[1] == dst:
                ports.append(dict(link[2]).get("port1"))
            elif link[1] == switch and link[0] == dst:
                ports.append(dict(link[2]).get("port2"))
        if len(ports) > 1:
            return ports
        else:
            return None

    def __discover_switches(self):
        '''
        Discover Switches

        Find all nodes in the given topology that have the `isSwitch` flag.
        '''
        switches = {}
        for node, data in self.topo.g.nodes(data=True):
            if data.get("isSwitch", False):
                dpid = self.__derive_dpid(node, dpid=data.get("dpid", None))
                switches[node] = dpid
        return switches

    def __derive_dpid(self, name, dpid=None):
        '''
        Derive DPID

        Straight up taken from the Mininet source code (2.3.0). Determines a
        DPID for a switch based on the numberic values in its name. Otherwise if
        a DPID has been given, check if it is valid.
        '''
        if dpid:
            dpid = dpid.replace(':', '')
            if not len(dpid) <= 16:
                print("🆘\tdpid too long fow switch: {}".format(name))
                sys.exit(1)
            try:
                dpid_int = int(dpid, 16)
                if dpid_int < 0:
                    print("🆘\tdpid should not be negative for switch: {}".format(name))
                    sys.exit(1)
            except:
                print("🆘\tdpid is not a hex value for switch: {}".format(name))
                sys.exit(1)
        else:
            nums = re.findall(r'\d+', name)
            if nums:
                dpid = hex(int(nums[0]))[2:]
            else:
                print("🆘\tcould not determine a dpid for switch: {}".format(name))
                sys.exit(1)
        return '0' * (16 - len(dpid)) + dpid

    def __create_vport_name(self, n):
        return self.VPORT_NAME_TEMPLATE.format(n)


parser = argparse.ArgumentParser()
parser.add_argument("--custom", help="File path for the topology file", type=open, required=True)
parser.add_argument("--topo", help="Topology within the file to generate vports.json for", type=str, required=True)
args = parser.parse_args()

exec(args.custom.read())
generator = VPortGenerator(topos.get(args.topo))
print(json.dumps(
    generator.generate(),
    sort_keys=True,
    indent=2,
    separators=(',', ': ')
))
