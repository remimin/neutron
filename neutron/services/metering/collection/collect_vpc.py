# -*- coding: utf-8 -*-
import collections
import os
import time
import subprocess
import datetime
import os.path
import socket
import json
import io

import eventlet
from neutron_lib import context
from oslo_concurrency import lockutils
from osprofiler import profiler
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_utils import fileutils
import six

from neutron_lib.utils import helpers
from neutron.agent.linux import ip_lib
from neutron.services.metering.common import constants as meter_const
from neutron.services.metering.common import utils as meter_utils
from oslo_utils import timeutils

import datetime

LOG = logging.getLogger(__name__)


class MonitorVPC(object):
    def __init__(self):
        LOG.debug('MonitorVPC init')
        self.meter_utils = meter_utils.MonitorUtils()
        self.netns = ip_lib.IpNetnsCommand(self)
        self.first_update = 0
        self.last_update = 0

    def __del__(self):
        LOG.debug('MonitorVPC destory')

    def get_ha_interface_in_namespace(self, ns):
        ip_wrapper = ip_lib.IPWrapper(namespace=ns)
        ip_devs = ip_wrapper.get_devices()

        for ip_dev in ip_devs:
            if 'ha-' in ip_dev.name:
                return ip_dev.name

    def get_cur_time(self):
        now_time = datetime.datetime.now()
        now = str(now_time.year) + '-' + str(now_time.month) + '-' + \
              str(now_time.day) + '  ' + str(now_time.hour) + ':' + \
              str(now_time.minute) + ':' + str(now_time.second)
        return now

    def get_linux_time(self):
        return time.time()

    def monitor_resource_vpc(self, log_handle, producer_dict):
        LOG.debug('-----Entry collect VPC-----')
        router_ns = set()
        vpc_counter = []
        try:
            now_time1 = datetime.datetime.now()
            cmd = '/usr/sbin/ip netns | grep qrouter'
            ret_list = self.meter_utils.monitor_util_cmd_execute_list(cmd)

            now_time2 = datetime.datetime.now()
            if len(ret_list) == 0:
                LOG.warning('collecting VPC but not found any router namespace...')
                return
            else:
                LOG.info('\n eslaped:%s ret_list=%s ', now_time2 - now_time1, ret_list)

            router_set = set(ret_list)
            for ns in router_set:
                if len(ns) >= meter_const.VROUTER_NS_LEN and meter_const.ROUTER_LABLE in ns:
                    ns = ns.split(' ')[0]
                    ns_uuid = ns[(meter_const.ROUTER_LABLE_LEN + 1):]
                    router_ns.add(ns)

                    #LOG.debug('-------router namespace:%s', ns)
                    ip_wrapper = ip_lib.IPWrapper(namespace=ns)
                    ip_devs = ip_wrapper.get_devices()
                    devs = {}
                    total_inpkt = 0
                    total_inter_bytes = 0
                    total_ext_pkgs = 0
                    total_ext_bytes = 0
                    #LOG.debug('-------------ip_devs:%s', ip_devs)
                    for ip_dev in ip_devs:
                        if ip_dev.name.startswith('qr') or ip_dev.name.startswith('qg'):
                            data = {'inter_pkts': 0, 'inter_bytes': 0, 'ext_pkts': 0, 'ext_bytes': 0}
                            ifcmd = ['ifconfig', ip_dev.name]
                            output = ip_wrapper.netns.execute(ifcmd, run_as_root=True, check_exit_code=False)
                            #LOG.debug('-------------output:%s', output)
                            for l in output.split('\n'):
                                l = l.strip()
                                #LOG.debug('-------------line:%s', l)
                                if l.startswith('RX packets'):
                                    parts = l.split(' ')
                                    #LOG.debug('-------------parts:%s', parts)
                                    data['inter_pkts'] = int(parts[2])
                                    data['inter_bytes'] = int(parts[5])
                                    total_inpkt += data['inter_pkts']
                                    total_inter_bytes += data['inter_bytes']
                                elif l.startswith('TX packets'):
                                    parts = l.split(' ')
                                    #LOG.debug('-------------parts:%s', parts)
                                    data['ext_pkts'] = int(parts[2])
                                    data['ext_bytes'] = int(parts[5])
                                    total_ext_pkgs += data['ext_pkts']
                                    total_ext_bytes += data['ext_bytes']
                            #LOG.debug('devname=%s inpkt=%s inbyte=%s outpkt=%s outbyte=%s', ip_dev.name, total_inpkt, total_inter_bytes, total_ext_pkgs,total_ext_bytes )
                            devs[ip_dev.name] = data
                    devs['total_inter_pkts'] = total_inpkt
                    devs['total_inter_bytes'] = total_inter_bytes
                    devs['total_ext_pkts'] = total_ext_pkgs
                    devs['total_ext_bytes'] = total_ext_bytes
                    devs['timestamp'] = time.time()
                    devs['uuid'] = ns
                    vpc_counter.append(devs)

            LOG.debug('-----Exit collect VPC-----')
        except Exception as e:
            LOG.error('analying VPC namespace failed...%(router_ns)s reason %(except)s', {'router_ns':router_ns,'except':e})
            return

        try:
            vpc_str = json.dumps(vpc_counter, ensure_ascii=False, indent=1)
            producer_dict['producer_vpc'].produce(bytes(vpc_str))
            LOG.info('===VPC string to kafka===%s', vpc_str)

            log_handle.logger.info(vpc_str)

        except Exception as e:
            LOG.error('reporting VPC counter failed...reason %(except)s', {'except':e})
            return
