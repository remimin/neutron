#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re
import netaddr
import socket

from neutron_lib import constants
from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.agent.linux import tc_lib
from neutron.common import exceptions

LOG = logging.getLogger(__name__)

QDISC_IN_REGEX = re.compile(r"qdisc ingress (\w+:) *")
QDISC_OUT_REGEX = re.compile(r"qdisc htb (\w+:) *")
FILTER_ID_REGEX = re.compile(r"filter protocol (.*?) u32 (fh|chain \d+ fh) (\w+::\w+) *")
FILTER_STATS_REGEX = re.compile(r"Sent (\w+) bytes (\w+) pkts *")
IPV4_ADDR_REGEX = re.compile(r"match ([a-f0-9]*)/ffffffff at (1[2,6]) *")
IPV6_32BIT_ADDR_REGEX = re.compile(r"match ([a-f0-9]*)/ffffffff at (\d+) ([(].*?[)])*")
IPV6_FULL_ADDR_REGEX = re.compile(r"match .*? ([a-f0-9:]*)/128 *")

IPV4_START_OF_HEADER_OFFSET = ('12', '16')
IPV6_START_OF_HEADER_OFFSET = ('8', '24')
IPV6_END_OF_HEADER_OFFSET = ('20', '36')


class FloatingIPTcCommandBase(ip_lib.IPDevice):

    def _execute_tc_cmd(self, cmd, **kwargs):
        cmd = ['tc'] + cmd
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        return ip_wrapper.netns.execute(cmd, run_as_root=True, **kwargs)

    def _get_qdiscs(self):
        cmd = ['qdisc', 'show', 'dev', self.name]
        return self._execute_tc_cmd(cmd)

    def _get_qdisc_id_for_filter(self, direction):
        qdisc_results = self._get_qdiscs().split('\n')
        for qdisc in qdisc_results:
            pattern = (QDISC_OUT_REGEX
                       if direction == constants.EGRESS_DIRECTION
                       else QDISC_IN_REGEX)
            m = pattern.match(qdisc)
            if m:
                # No chance to get multiple qdiscs
                return m.group(1)

    def _add_qdisc(self, direction):
        if direction == constants.EGRESS_DIRECTION:
            args = ['root', 'handle', '1:', 'htb']
        else:
            args = ['ingress']
        cmd = ['qdisc', 'add', 'dev', self.name] + args
        self._execute_tc_cmd(cmd)

    def _get_filters(self, qdisc_id):
        cmd = ['-p', '-s', '-d', 'filter', 'show', 'dev', self.name,
               'parent', qdisc_id, 'prio', 1]
        return self._execute_tc_cmd(cmd)

    def _get_filters_ips_map_v4(self, qdisc_id, ip):
        filter_ip_map = dict()
        filter_id = ''
        is_first_match_line = bool()
        cmd = ['-s', '-d', 'filter', 'show', 'dev', self.name,
               'parent', qdisc_id, 'prio', 1]
        filters_output = self._execute_tc_cmd(cmd)
        if not filters_output:
            raise exceptions.FilterIDForIPNotFound(ip=ip)
        filter_lines = filters_output.split('\n')
        for line in filter_lines:
            line = line.strip()
            m_filter_id = FILTER_ID_REGEX.match(line)
            m_ipv4_addr = IPV4_ADDR_REGEX.match(line)
            if m_filter_id and m_filter_id.group(1) == 'all':
                filter_id = m_filter_id.group(3)
                is_first_match_line = True
                continue
            if m_ipv4_addr and len(filter_id) != 0 and is_first_match_line:
                ipv4_addr = '0x' + m_ipv4_addr.group(1)
                ipv4_header_offset = m_ipv4_addr.group(2)
                if ipv4_header_offset in IPV4_START_OF_HEADER_OFFSET:
                    filter_ip_map[filter_id] = \
                        str(netaddr.IPAddress(ipv4_addr))
            is_first_match_line = False
        return filter_ip_map

    @staticmethod
    def _format_ipv6_address(ipv6_addr_offset_map):
        ipv6_addr = ''
        ipv6_addr_list = list()
        for offset in sorted(ipv6_addr_offset_map):
            ipv6_addr_list.append(ipv6_addr_offset_map[offset][0:4])
            ipv6_addr_list.append(ipv6_addr_offset_map[offset][4:8])

        for ipv6_str in ipv6_addr_list:
            ipv6_addr += ipv6_str + ':'
        ipv6_addr = ipv6_addr[:-1]
        return ipv6_addr

    def _get_filters_ips_map_v6(self, qdisc_id, ip):
        ipv6_addr_offset_map = dict()
        filter_ip_map = dict()
        filter_id = ''
        cmd = ['-s', '-d', 'filter', 'show', 'dev', self.name,
               'parent', qdisc_id, 'prio', 1]
        filters_output = self._execute_tc_cmd(cmd)
        if not filters_output:
            raise exceptions.FilterIDForIPNotFound(ip=ip)
        filter_lines = filters_output.split('\n')
        for line in filter_lines:
            line = line.strip()
            m_filter_id = FILTER_ID_REGEX.match(line)
            m_ipv6_addr = IPV6_32BIT_ADDR_REGEX.match(line)
            if m_filter_id and m_filter_id.group(1) == 'all':
                filter_id = m_filter_id.group(3)
                continue
            if m_ipv6_addr and len(filter_id) != 0:
                part_of_ipv6_addr = m_ipv6_addr.group(1)
                ipv6_header_offset = m_ipv6_addr.group(2)
                if ipv6_header_offset in IPV6_START_OF_HEADER_OFFSET:
                    ipv6_addr_offset_map.clear()
                ipv6_addr_offset_map[int(ipv6_header_offset)] \
                    = part_of_ipv6_addr
                if ipv6_header_offset in IPV6_END_OF_HEADER_OFFSET:
                    ipv6_addr = \
                        self._format_ipv6_address(ipv6_addr_offset_map)
                    filter_ip_map[filter_id] = ipv6_addr
                    filter_id = ''
                    ipv6_addr_offset_map.clear()
        return filter_ip_map

    def _get_filterid_for_ip(self, qdisc_id, ip):
        filterids_for_ip = list()
        if netaddr.IPAddress(ip).version == constants.IP_VERSION_4:
            filters_ips_map = self._get_filters_ips_map_v4(qdisc_id, ip)
            for key, value in filters_ips_map.items():
                if ip == value:
                    filterids_for_ip.append(key)
        else:
            filters_ips_map = self._get_filters_ips_map_v6(qdisc_id, ip)
            for key, value in filters_ips_map.items():
                if socket.inet_pton(socket.AF_INET6, ip) == \
                        socket.inet_pton(socket.AF_INET6, value):
                    filterids_for_ip.append(key)
        if len(filterids_for_ip) > 1:
            raise exceptions.MultipleFilterIDForIPFound(ip=ip)
        elif len(filterids_for_ip) == 0:
            raise exceptions.FilterIDForIPNotFound(ip=ip)
        return filterids_for_ip[0]

    def _del_filter_by_id(self, qdisc_id, filter_id):
        cmd = ['filter', 'del', 'dev', self.name,
               'parent', qdisc_id,
               'prio', 1, 'handle', filter_id, 'u32']
        self._execute_tc_cmd(cmd)

    def _get_qdisc_filters(self, qdisc_id):
        filterids = []
        filters_output = self._get_filters(qdisc_id)
        if not filters_output:
            return filterids
        filter_lines = filters_output.split('\n')
        for line in filter_lines:
            line = line.strip()
            m = FILTER_ID_REGEX.match(line)
            if m:
                filter_id = m.group(2)
                filterids.append(filter_id)
        return filterids

    def _add_filter(self, qdisc_id, direction, ip, rate, burst):
        rate_value = "%s%s" % (rate, tc_lib.BW_LIMIT_UNIT)
        burst_value = "%s%s" % (
            tc_lib.TcCommand.get_ingress_qdisc_burst_value(rate, burst),
            tc_lib.BURST_UNIT
        )
        protocol = ['protocol', 'all']
        prio = ['prio', 1]
        _match = 'src' if direction == constants.EGRESS_DIRECTION else 'dst'
        match = ['u32', 'match', 'ip', _match, ip]
        police = ['police', 'rate', rate_value, 'burst', burst_value,
                  'mtu', '64kb', 'drop', 'flowid', ':1']
        args = protocol + prio + match + police
        cmd = ['filter', 'add', 'dev', self.name,
               'parent', qdisc_id] + args
        self._execute_tc_cmd(cmd)

    def _add_v6_filter(self, qdisc_id, direction, ip, rate, burst):
        rate_value = "%s%s" % (rate, tc_lib.BW_LIMIT_UNIT)
        burst_value = "%s%s" % (
            tc_lib.TcCommand.get_ingress_qdisc_burst_value(rate, burst),
            tc_lib.BURST_UNIT
        )
        protocol = ['protocol', 'all']
        prio = ['prio', 1]
        _match = 'src' if direction == constants.EGRESS_DIRECTION else 'dst'
        match = ['u32', 'match', 'ip6', _match, ip]
        police = ['police', 'rate', rate_value, 'burst', burst_value,
                  'mtu', '64kb', 'drop', 'flowid', ':1']
        args = protocol + prio + match + police
        cmd = ['filter', 'add', 'dev', self.name,
               'parent', qdisc_id] + args
        self._execute_tc_cmd(cmd)

    def _get_or_create_qdisc(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            self._add_qdisc(direction)
            qdisc_id = self._get_qdisc_id_for_filter(direction)
            if not qdisc_id:
                raise exceptions.FailedToAddQdiscToDevice(direction=direction,
                                                          device=self.name)
        return qdisc_id


class FloatingIPTcCommand(FloatingIPTcCommandBase):

    def clear_all_filters(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        filterids = self._get_qdisc_filters(qdisc_id)
        for filter_id in filterids:
            self._del_filter_by_id(qdisc_id, filter_id)

    def get_filter_id_for_ip(self, direction, ip):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        return self._get_filterid_for_ip(qdisc_id, ip)

    def get_existing_filter_ids(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        return self._get_qdisc_filters(qdisc_id)

    def delete_filter_ids(self, direction, filterids):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        for filter_id in filterids:
            self._del_filter_by_id(qdisc_id, filter_id)

    def set_ip_rate_limit(self, direction, ip, rate, burst):
        qdisc_id = self._get_or_create_qdisc(direction)
        try:
            filter_id = self._get_filterid_for_ip(qdisc_id, ip)
            LOG.debug("Filter %(filter)s for IP %(ip)s in %(direction)s "
                      "qdisc already existed, removing.",
                      {'filter': filter_id,
                       'ip': ip,
                       'direction': direction})
            self._del_filter_by_id(qdisc_id, filter_id)
        except exceptions.FilterIDForIPNotFound:
            pass
        LOG.debug("Adding filter for IP %(ip)s in %(direction)s.",
                  {'ip': ip,
                   'direction': direction})
        if netaddr.IPAddress(ip).version == constants.IP_VERSION_4:
            self._add_filter(qdisc_id, direction, ip, rate, burst)
        else:
            self._add_v6_filter(qdisc_id, direction, ip, rate, burst)

    def clear_ip_rate_limit(self, direction, ip):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        try:
            filter_id = self._get_filterid_for_ip(qdisc_id, ip)
            self._del_filter_by_id(qdisc_id, filter_id)
        except exceptions.FilterIDForIPNotFound:
            LOG.debug("No filter found for IP %(ip)s in %(direction)s, "
                      "skipping deletion.",
                      {'ip': ip,
                       'direction': direction})
