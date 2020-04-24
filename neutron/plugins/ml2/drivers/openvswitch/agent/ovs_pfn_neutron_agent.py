# Handle private floating network.

import netaddr
import re

from neutron_lib import constants as n_const
from oslo_log import log as logging
import oslo_messaging
from osprofiler import profiler

from neutron.agent.common import ip_lib
from neutron.agent.common import ovs_lib
from neutron.agent.linux import interface as interface_driver
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants

LOG = logging.getLogger(__name__)


class PFNPort(object):
    def __init__(self, id, ofport, mac, device_owner):
        self.id = id
        self.mac = mac
        self.ofport = ofport
        self.device_owner = device_owner
        # Subnets
        self.subnets = set()
        # Just save port associating flow(in_port, out_port, ip, mac)
        self.flows = []

    def __str__(self):
        return ("OVSPort: id = %s, ofport = %s, mac = %s, "
                "device_owner = %s, subnets = %s, flows = %s" %
                (self.id, self.ofport, self.mac,
                 self.device_owner, self.subnets,
                 self.flows))

    def add_subnet(self, subnet_id):
        self.subnets.add(subnet_id)

    def remove_subnet(self, subnet_id):
        self.subnets.remove(subnet_id)

    def remove_all_subnets(self):
        self.subnets.clear()

    def get_subnets(self):
        return self.subnets
    
    def add_flow(self, kwargs):
        self.flows.append(kwargs)

    def remove_flow(self, kwargs):
        self.flows.remove(kwargs)

    def remove_all_flows(self):
        self.flows.clear()

    def get_flows(self):
        return self.flows

    def get_device_owner(self):
        return self.device_owner

    def get_mac(self):
        return self.mac

    def get_ofport(self):
        return self.ofport


@profiler.trace_cls("ovs_pfn_agent")
class OVSPFNNeutronAgent(object):
    '''
        Implements OVS-based private floating network.
    '''
    # history
    #   1.0 Initial version

    def __init__(self, context, plugin_rpc, conf, agent_id, int_br, tun_br,
                 bridge_mappings, phys_brs, int_ofports, phys_ofports,
                 patch_int_ofport=constants.OFPORT_INVALID,
                 patch_tun_ofport=constants.OFPORT_INVALID,
                 host=None, enable_tunneling=False):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.conf = conf
        self.agent_id = agent_id
        self.bridge_mappings = bridge_mappings
        self.phys_brs = phys_brs
        self.int_ofports = int_ofports
        self.phys_ofports = phys_ofports
        
        self.reset_ovs_parameters(int_br, tun_br, 
                                  patch_int_ofport, patch_tun_ofport)
        
        self.host = host
        self.enable_tunneling = enable_tunneling
        
        self.privatefloating_info = self.plugin_rpc.get_privatefloating_info(
                self.context, agent_id=self.agent_id, host=self.host)
        
        LOG.info("[FPN] privatefloating_info: %s" % self.privatefloating_info)
        
        self.enable_private_floating = False
        self.arp_timeout = 300
        
        if self.privatefloating_info:
            self.enable_private_floating = \
                self.privatefloating_info.get('privatefloating_enable')
            self.arp_timeout = \
                self.privatefloating_info.get('arp_timeout')
        
        self.enable_firewall = False
        OVS_DRIVERS = [
            'openvswitch',
            'neutron.agent.linux.openvswitch_firewall:OVSFirewallDriver'
        ]
        if self.conf.SECURITYGROUP.firewall_driver in OVS_DRIVERS:
            self.enable_firewall = True
        
        self.reset_pfn_parameters()
        
    
    def reset_ovs_parameters(self, int_br, tun_br,
                             patch_int_ofport, patch_tun_ofport):
        '''Reset the openvswitch parameters'''
        self.int_br = int_br
        self.tun_br = tun_br
        self.patch_int_ofport = patch_int_ofport
        self.patch_tun_ofport = patch_tun_ofport
        # Normally, patch_int_ofport is pfip_physnet_ofport
        self.pfip_physnet_ofport = constants.OFPORT_INVALID
    
    def reset_pfn_parameters(self):
        '''Reset the PFN parameters'''
        self.local_ports = {}
        self.privatefloating_subnets = {}
        self.ns_privatefloating_port = {}
        self.privatefloating_network = {}
        self.privatefloating_subnet_dict = {}
        self.ns_privatefloating_mac = ''
        self._update_cookie = None
    
    def is_privatefloating_enabled(self):
        return self.enable_private_floating
    
    def _check_pfn_physnet_ofport(self):
        if self.pfip_physnet_ofport == ovs_lib.INVALID_OFPORT:
            if self.privatefloating_network:
                physnet = self.privatefloating_network.get('provider:physical_network')
                self.pfip_physnet_ofport = self.int_ofports[physnet]
        
    def _add_flow(self, **kwargs):
        if self._update_cookie:
            kwargs['cookie'] = self._update_cookie

        LOG.debug("[FPN] add flow: %s " % kwargs)
        self.int_br.add_flow(**kwargs)
 
    def _delete_flows(self, **kwargs):
        new_kwargs = {}
        
        # Filter invalid item
        for key, value in kwargs.items():
            if key != 'priority':
                if key == 'actions':
                    # Exclude () content
                    valid_action = re.sub("\\(.*?\\)", "", value)
                    for action in valid_action.split(","):
                        pattern = r'output:'
                        match_obj = re.match(pattern, action)
                        if match_obj is not None:
                            port = re.sub(pattern, "", action)
                            new_kwargs['out_port'] = port
                else:
                    new_kwargs[key] = value
        
        LOG.debug("[FPN] delete flow: %s " % new_kwargs)
        self.int_br.delete_flows(**new_kwargs)

    
    def _init_privatefloating_flows(self):
        '''
            Initialize flows for privatefloating in integrate bridge
        '''
        # Default flow for arp responser
        col_kwargs = {
            'table': constants.PFN_ARP_RESPONSER_TABLE,
            'priority':0,
            'proto': 'arp',
            'actions': "NORMAL" 
        }
        self._add_flow(**col_kwargs)
        
        # Default flow for private floating egress process
        col_kwargs = {
            'table': constants.PFN_BASE_EGRESS_TABLE,
            'priority': 0,
            'actions': "NORMAL"
        }
        self._add_flow(**col_kwargs)
        
        # Default flow for route
        col_kwargs = {
            'table': constants.PFN_RULES_ROUTE_EGRESS_TABLE,
            'priority': 0,
            'actions': "NORMAL"
        }
        self._add_flow(**col_kwargs)
        
        # Default flow for egress traffic
        col_kwargs = {
            'table': constants.PFN_EGRESS_TRAFFIC_TABLE,
            'priority': 0,
            'actions': "NORMAL"
        }
        self._add_flow(**col_kwargs)
        
        # Default flow for ingress traffic
        col_kwargs = {
            'table': constants.PFN_INGRESS_TRAFFIC_TABLE,
            'priority': 0,
            'actions': "NORMAL"
        }
        self._add_flow(**col_kwargs)
        
        # Default flow for private floating ingress process  
        col_kwargs = {
            'table': constants.LOCAL_SWITCHING,
            'priority': 1,
            'actions': "resubmit(,%d)" % (constants.PFN_BASE_INGRESS_TABLE)
        }
        self._add_flow(**col_kwargs)

        col_kwargs = {
            'table': constants.PFN_BASE_INGRESS_TABLE,
            'priority': 0,
            'actions': "resubmit(,%d)" % (constants.TRANSIENT_TABLE)
        }
        self._add_flow(**col_kwargs)
        
        
        # [Egress] Decide process pipeline
        # [Ingress] see _bind_pf_port function
        if self.enable_firewall:
            # Enable ovs firewall case: need to redirect last flow
            # security group egress(accepted traffic) -> privatefloating entrance
            col_kwargs = {
                'table': constants.ACCEPTED_EGRESS_TRAFFIC_TABLE,
                'priority': 5,
                'actions': "resubmit(,%d)" % (constants.PFN_BASE_EGRESS_TABLE)
            }
            self._add_flow(**col_kwargs)
            
            # Expecial traffic for port without security group
            col_kwargs = {
                'table': constants.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
                'priority': 5,
                'actions': "resubmit(,%d)" % (constants.PFN_BASE_EGRESS_TABLE)
            }
            self._add_flow(**col_kwargs)
        else:
            # No ovs firewall case
            # Egress entrance
            col_kwargs = {
                'table': constants.TRANSIENT_TABLE,
                'priority': 5,
                'actions': "resubmit(,%d)" % (constants.PFN_BASE_EGRESS_TABLE)
            }
            self._add_flow(**col_kwargs)
         
        
    def setup_privatefloating(self):
        if not self.is_privatefloating_enabled():
            return
        
        self.privatefloating_network = self.privatefloating_info.get('privatefloating_network',{})
        if not self.privatefloating_network:
            LOG.warning("[FPN] privatefloating is enabled but privatefloating network is not exits!")
            return
        
        # Create a new namespace and a ovs(internal) device in it.
        network_id = self.privatefloating_network.get('id')
        ns_name = "pfip-%s" % network_id
        
        self.ns_privatefloating_port = self.privatefloating_info.get('privatefloating_port',{})
        if not self.ns_privatefloating_port:
            LOG.warning("[FPN] privatefloating is enabled but privatefloating port is not exits!")
            return
        
        port_id = self.ns_privatefloating_port.get('id')
        interfaceObj = interface_driver.OVSInterfaceDriver(self.conf)
        tap_name = "tap%s" % port_id
        tap_name = tap_name[:14]
        mac_address = self.ns_privatefloating_port.get('mac_address')
        # this mac is important!!!
        self.ns_privatefloating_mac = mac_address
        
        interfaceObj.plug(network_id, port_id, tap_name, mac_address, 
                          namespace=ns_name)
        
        # set ipv4.ip_forward
        ip_wrapper_root = ip_lib.IPWrapper()
        ip_wrapper = ip_wrapper_root.ensure_namespace(ns_name)
        ip_wrapper.netns.execute(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        
        # Handle l3(cidr) settings in this namespace
        for subnet1 in self.privatefloating_network.get('subnets_detail',[]):
            LOG.debug("[FPN] private floating subnet: \n%s", subnet1)
            self.privatefloating_subnet_dict[subnet1['id']] = subnet1
        
        ips = []
        for fixed_ip in self.ns_privatefloating_port.get('fixed_ips',[]):
            if self.privatefloating_subnet_dict.has_key(fixed_ip['subnet_id']):
                cidr = self.privatefloating_subnet_dict[fixed_ip['subnet_id']]['cidr']
                mask = cidr[cidr.rindex('/')+1:len(cidr)]
                ip = '%s/%s' % (fixed_ip['ip_address'], mask)
                ips.append(ip)
                
        LOG.debug("[FPN] init privatefloating ip %s" % ips) 
        interfaceObj.init_l3(tap_name, ips, namespace=ns_name)
        
        # Handle route settings in this namespace
        ipdevice_obj = ip_lib.IPDevice(tap_name, ns_name)
        
        for subnet1 in self.privatefloating_network.get('subnets_detail',[]):
            LOG.debug("[FPN] private floating subnet detail: \n%s" % subnet1)
            subnet_routes = subnet1['host_routes']
            
            for route in subnet_routes:
                dest = route['destination']
                nexthop = route['nexthop']
                #nexthop_value = netaddr.IPAddress(nexthop).value
                ipdevice_obj.route.add_route(dest, nexthop)   
        
        # Check physnet port for private floating
        self._check_pfn_physnet_ofport()
        
        # Init flows
        self._init_privatefloating_flows()
        
        
    def _bind_npf_port(self, port, fixed_ips, device_owner, net_uuid, 
                       local_vlan_map):
        '''
            Handle none-privatefloating type port, like normal port(device_owner=nova-comuter)
            such as:
                * port(tapxxx) which have two subnet, privatefloating subnet and normal subnet
                * port(tapxxx) which have one subnet which privatefloating network
        '''
        pfnport = PFNPort(port.vif_id, port.ofport, port.vif_mac, device_owner)
        
        # collect all of the ipv4 addresses and cidrs that belong to the port
        # Not support ipv6 now!!!
        fixed_ipv4s = [f for f in fixed_ips if netaddr.IPNetwork(f['ip_address']).version == 4]
        
        LOG.info("[FPN] fixed_ips: %s" % fixed_ipv4s)
        
        if len(fixed_ipv4s) == 2:
            # port(tapxxx) which have two subnet, privatefloating subnet and normal subnet
            LOG.debug("[FPN] privatefloating_subnet_dict: %s" % self.privatefloating_subnet_dict)
            
            pfnport.add_subnet(fixed_ipv4s[0]['subnet_id'])
            pfnport.add_subnet(fixed_ipv4s[1]['subnet_id'])
            
            privatefloating_ip = ''
            fixed_ip = ''
            
            # Find privatefloating-ip from ip which subnet is privatefloating subnet.
            if self.privatefloating_subnet_dict.has_key(fixed_ipv4s[0]['subnet_id']):
                privatefloating_ip = fixed_ipv4s[0]['ip_address']
                fixed_ip = fixed_ipv4s[1]['ip_address']
            elif self.privatefloating_subnet_dict.has_key(fixed_ipv4s[1]['subnet_id']):
                privatefloating_ip = fixed_ipv4s[1]['ip_address']
                fixed_ip = fixed_ipv4s[0]['ip_address']
                
            if privatefloating_ip:
                # Add port egress traffic path
                col_kwargs = {
                    'table': constants.PFN_BASE_EGRESS_TABLE,
                    'priority': 5,
                    'in_port': port.ofport,
                    'actions': "resubmit(,%d)" % constants.PFN_RULES_ROUTE_EGRESS_TABLE
                }
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
                
                # Add port egress traffic path, translate fixed-ip to privatefloating-ip
                col_kwargs = {
                    'table': constants.PFN_RULES_EGRESS_TABLE,
                    'priority': 20,
                    'proto': 'ip',
                    'in_port': port.ofport,
                    'nw_src': fixed_ip,
                    'actions': "mod_nw_src:%s,resubmit(,%d)" % (
                        privatefloating_ip,
                        constants.PFN_EGRESS_TRAFFIC_TABLE
                    )
                }
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
                
                # Decide process pipeline
                if self.enable_firewall:
                    # Add port ingress traffic path, translate privatefloating-ip to fixed-ip
                    col_kwargs = {
                        'table': constants.PFN_RULES_INGRESS_TABLE,
                        'priority': 20,
                        'proto': 'ip',
                        'nw_dst': privatefloating_ip,
                        'actions': "mod_nw_dst:%s,mod_dl_src:%s,mod_dl_dst:%s,"
                            "resubmit(,%d)" % (
                            fixed_ip,
                            self.ns_privatefloating_mac,
                            port.vif_mac,
                            constants.PFN_INGRESS_TRAFFIC_TABLE
                        )
                    }
                    self._add_flow(**col_kwargs)
                    pfnport.add_flow(col_kwargs)
                    
                    # Redirect to firewall ingress entrace
                    col_kwargs = {
                        'table': constants.PFN_INGRESS_TRAFFIC_TABLE,
                        'priority': 20,
                        'dl_dst': port.vif_mac,
                        'actions': "load:%s->NXM_NX_REG5[],"
                            "load:%s->NXM_NX_REG6[],strip_vlan,resubmit(,%d)" % (
                            "0x{:x}".format(port.ofport),
                            "0x{:x}".format(local_vlan_map.vlan),
                            constants.BASE_INGRESS_TABLE
                        )
                    }
                    self._add_flow(**col_kwargs)
                    pfnport.add_flow(col_kwargs)
                else:
                    # Add port ingress traffic path, translate privatefloating-ip to fixed-ip
                    col_kwargs = {
                        'table': constants.PFN_RULES_INGRESS_TABLE,
                        'priority':20,
                        'proto': 'ip',
                        'nw_dst': privatefloating_ip,
                        'actions': "mod_nw_dst:%s,mod_dl_src:%s,mod_dl_dst:%s,"
                            "strip_vlan,output:%d" % (
                            fixed_ip,
                            self.ns_privatefloating_mac,
                            port.vif_mac,
                            port.ofport
                        )
                    }
                    self._add_flow(**col_kwargs)
                    pfnport.add_flow(col_kwargs)
                
                mac_value = self.ns_privatefloating_mac
                
                ### Cross-node case(router nexthop in annother node)
                # [ARP] arp request packet(VM-privatefloating_ip) from patch port
                # response pfip namespace MAC
                col_kwargs = {
                    'table': constants.PFN_ARP_RESPONSER_TABLE,
                    'priority':20,
                    'proto': 'arp',
                    'arp_op': 1,
                    'in_port': self.pfip_physnet_ofport,
                    'arp_tpa':privatefloating_ip,
                    'actions': "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
                        "mod_dl_src:%s,"
                        "load:0x2->NXM_OF_ARP_OP[],"
                        "move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],"
                        "move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],"
                        "load:0x%s->NXM_NX_ARP_SHA[],"
                        "load:%s->NXM_OF_ARP_SPA[],in_port" % (
                        self.ns_privatefloating_mac,
                        mac_value.replace(':',''),
                        "0x{:04x}".format(netaddr.IPAddress(privatefloating_ip).value)
                    )
                }
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
                
                ### Inter-node case(router nexthop in this node)
                # [ARP] arp request packet(VM-privatefloating_ip) in integrate bridge
                # response port MAC
                col_kwargs = {
                    'table': constants.PFN_ARP_RESPONSER_TABLE,
                    'priority':10,
                    'proto': 'arp',
                    'arp_op': 1,
                    'arp_tpa':privatefloating_ip,
                    'actions': "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
                        "mod_dl_src:%s,"
                        "load:0x2->NXM_OF_ARP_OP[],"
                        "move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],"
                        "move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],"
                        "load:0x%s->NXM_NX_ARP_SHA[],"
                        "load:%s->NXM_OF_ARP_SPA[],in_port" % (
                        port.vif_mac,
                        port.vif_mac.replace(':',''),
                        "0x{:04x}".format(netaddr.IPAddress(privatefloating_ip).value)
                    )
                }
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
                
        elif len(fixed_ipv4s) == 1: 
            if net_uuid == self.privatefloating_network.get('id'):
                # normal port(tapxxx) which have one subnet(privatefloating network)
                pfnport.add_subnet(fixed_ipv4s[0]['subnet_id'])
                
                fixed_ip_address = fixed_ipv4s[0]['ip_address']
                
                # Add port egress traffic fast path, skip arp flood
                col_kwargs = {
                    'table': constants.PFN_EGRESS_TRAFFIC_TABLE,
                    'priority':20,
                    'proto': 'ip',
                    'reg2': "0x{:04x}".format(netaddr.IPAddress(fixed_ip_address).value),
                    'actions': "mod_dl_dst:%s,strip_vlan,output:%d" % (
                        port.vif_mac,
                        port.ofport
                    )
                }
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
                
                # Add port ingress traffic entrance
                col_kwargs = {
                    'table': constants.PFN_BASE_INGRESS_TABLE,
                    'priority': 10,
                    'proto': 'arp',
                    'in_port': port.ofport,
                    'actions': "resubmit(,%d)" % (constants.PFN_ARP_RESPONSER_TABLE)
                } 
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
                
                col_kwargs = {
                    #'table': constants.LOCAL_SWITCHING,
                    #this port type flows in LOCAL_SWITCHING table will been cleaned ???
                    'table': constants.PFN_BASE_INGRESS_TABLE,
                    'priority': 5,
                    'in_port': port.ofport,
                    'actions': "resubmit(,%d)" % (constants.PFN_RULES_INGRESS_TABLE)
                }
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
        else:
            LOG.warning("[FPN] not found ipv4 address!!!") 
        
        LOG.info("[FPN] pfnport: %s" % pfnport)        
        self.local_ports[port.vif_id] = pfnport       
                
    
    def _bind_pf_port(self, port, local_vlan_map, segmentation_id):
        '''
            Handle privatefloating type port(device_owner=network:privatefloating).
            such as:
                * port(tapxxx) which have one privatefloating ip in pfip namespace
        '''
        if not self.ns_privatefloating_port:
            return
        
        pfnport = PFNPort(port.vif_id, port.ofport, port.vif_mac, 
                          n_const.DEVICE_OWNER_PRIVATEFLOATING)
        
        ### Egress flows
        # Default egress flow: ip
        col_kwargs = {
            'table': constants.PFN_EGRESS_TRAFFIC_TABLE,
            'priority':5,
            'proto': 'ip',
            'actions': "strip_vlan,mod_dl_dst:%s,output:%d" % (
                self.ns_privatefloating_mac,
                port.ofport
            )
        }
        self._add_flow(**col_kwargs)
        pfnport.add_flow(col_kwargs)
        
        # Private floating netwrok handle, only one subnet normally
        for subnet_id in self.privatefloating_network.get('subnets',[]):
            pfnport.add_subnet(subnet_id)

        for subnet in self.privatefloating_network.get('subnets_detail',[]):
            LOG.debug("[FPN] private floating subnet detail: \n%s" % subnet)
            subnet_routes = subnet['host_routes']
            
            # Route table
            for route in subnet_routes:
                nexthop = route['nexthop']
                target = route['destination']
                nexthop_value = netaddr.IPAddress(nexthop).value
                
                ### Cross-node case(router nexthop in annother node)
                # [target IP] packet from patch port
                # Egress flow, save nexthop-ip for egress fast path
                col_kwargs = {
                    'table':constants.PFN_RULES_ROUTE_EGRESS_TABLE,
                    'proto':'ip',
                    'priority':20,
                    'in_port':self.pfip_physnet_ofport,
                    'nw_dst':target,
                    'actions': "load:%s->reg2, resubmit(,%d)" % (
                        "0x{:04x}".format(nexthop_value),
                        constants.PFN_RULES_EGRESS_TABLE
                    )
                } 
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
                ### Cross-node case end
                
                ### Inter-node case(router nexthop in this node)
                # [target IP] packet for router
                # Egress flow, save nexthop-ip for egress fast path
                col_kwargs = {
                    'table': constants.PFN_RULES_ROUTE_EGRESS_TABLE,
                    'proto': 'ip',
                    'priority': 10,
                    'nw_dst': target,
                    'actions': "load:%s->reg2,mod_vlan_vid:%d,resubmit(,%d)" % (
                        "0x{:04x}".format(nexthop_value),
                        ### vlanid for learn flow process
                        local_vlan_map.vlan,
                        constants.PFN_RULES_EGRESS_TABLE
                    )
                }
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
                ### Inter-node case end
                
                # [nexthop] ARP responser flow
                # arp response from patch port
                col_kwargs = {
                    'table': constants.PFN_ARP_RESPONSER_TABLE,
                    'priority':20,
                    'in_port': self.pfip_physnet_ofport,
                    'proto': 'arp',
                    'arp_op': 2,
                    'arp_spa': nexthop,
                    'actions': "learn(table=%d,priority=10,hard_timeout=%d,"
                        "fin_idle_timeout=60,fin_hard_timeout=%d,"
                        "reg2=%s,load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
                        "load:0x%s->NXM_OF_ETH_SRC[],"
                        "load:%d->OXM_OF_VLAN_VID[],"
                        "load:%d->NXM_OF_IN_PORT[],"
                        "output:NXM_OF_IN_PORT[]),normal" % (
                            constants.PFN_EGRESS_TRAFFIC_TABLE,
                            self.arp_timeout,
                            self.arp_timeout,
                            "0x{:04x}".format(nexthop_value),
                            self.ns_privatefloating_mac.replace(':',''),
                            local_vlan_map.vlan,
                            port.ofport
                    )
                }
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
                
                # arp response in integrate bridge 
                col_kwargs = {
                    'table': constants.PFN_ARP_RESPONSER_TABLE,
                    'priority':10,
                    'proto': 'arp',
                    'arp_op': 2,
                    'arp_spa': nexthop,
                    'actions': "learn(table=%d,priority=10,hard_timeout=%d,"
                        "fin_idle_timeout=60,fin_hard_timeout=%d,"
                        "reg2=%s,load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
                        "load:0x%s->NXM_OF_ETH_SRC[],"
                        "load:%d->OXM_OF_VLAN_VID[],"
                        "load:%d->NXM_OF_IN_PORT[],"
                        "output:NXM_OF_IN_PORT[]),normal" % (
                            constants.PFN_EGRESS_TRAFFIC_TABLE,
                            self.arp_timeout,
                            self.arp_timeout,
                            "0x{:04x}".format(nexthop_value),
                            self.ns_privatefloating_mac.replace(':',''),
                            local_vlan_map.vlan,
                            self.pfip_physnet_ofport
                    )
                }
                self._add_flow(**col_kwargs)
                pfnport.add_flow(col_kwargs)
        
        ### Ingress flows
        # Default ingress flow
        col_kwargs = {
            'table': constants.PFN_RULES_INGRESS_TABLE,
            'priority': 0,
            'proto': 'ip',
            'actions': "normal"
        }
        self._add_flow(**col_kwargs)
        
        ### Cross-node case
        # Ingress entrance, all ingress traffic after privatefloating handle
        col_kwargs = {
            'table': constants.LOCAL_SWITCHING,
            'priority': 10,
            'in_port': self.pfip_physnet_ofport,
            'dl_vlan': segmentation_id,
            'actions': "mod_vlan_vid:%d,resubmit(,%d)" % (
                local_vlan_map.vlan,
                constants.PFN_BASE_INGRESS_TABLE
            )
        }
        self._add_flow(**col_kwargs)
        pfnport.add_flow(col_kwargs)
        
        col_kwargs = {
            'table': constants.PFN_BASE_INGRESS_TABLE,
            'priority': 10,
            'proto': 'arp',
            'in_port': self.pfip_physnet_ofport,
            'actions': "resubmit(,%d)" % (constants.PFN_ARP_RESPONSER_TABLE)
        }
        self._add_flow(**col_kwargs)
        pfnport.add_flow(col_kwargs)
        
        col_kwargs = {
            'table': constants.PFN_BASE_INGRESS_TABLE,
            'priority': 5,
            'in_port': self.pfip_physnet_ofport,
            'actions': "resubmit(,%d)" % (constants.PFN_RULES_INGRESS_TABLE)
        }
        self._add_flow(**col_kwargs)
        pfnport.add_flow(col_kwargs)
        ### Cross-node case end
        
        ### Inter-node case don't need handle
        
        LOG.info("[FPN] pfnport: %s" % pfnport)      
        self.local_ports[port.vif_id] = pfnport
           

    def bind_port_to_pfn(self, port, net_uuid, local_vlan_map, segmentation_id,
                         fixed_ips, device_owner):
        if not self.enable_private_floating:
            return
        
        LOG.info("[FPN] bind port: %s" % port)
        
        if device_owner == n_const.DEVICE_OWNER_PRIVATEFLOATING:
            self._bind_pf_port(port, local_vlan_map, segmentation_id)
        else:
            self._bind_npf_port(port, fixed_ips, device_owner, net_uuid, 
                                local_vlan_map)
        
        
    def unbind_port_from_pfn(self, port):
        if not self.enable_private_floating:
            return
        
        LOG.info("[FPN] unbind port: %s" % port)
        
        pfnport = self.local_ports[port.vif_id]
        LOG.info("[FPN] pfnport: %s" % pfnport)
        flows = pfnport.get_flows()
        
        for flow in flows:
            self._delete_flows(**flow)
        
        # release port state
        self.local_ports.pop(port.vif_id, None)
        
        