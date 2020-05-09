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

from neutron.services.metering.common import constants as meter_const
from neutron.services.metering.common import utils as monitor_utils

from neutron.agent.linux import ip_lib
from neutron_lib.utils import helpers
from neutron.agent.linux import utils as neutron_utils
from oslo_utils import timeutils
import datetime

LOG = logging.getLogger(__name__)


class MonitorRouter(object):
    def __init__(self):
        LOG.debug('MonitorRouter init')
        self.monitorutils = monitor_utils.MonitorUtils()

    def get_ha_interface_in_namespace(self, ns):
        ip_wrapper = ip_lib.IPWrapper(namespace=ns)
        ip_devs = ip_wrapper.get_devices()

        for ip_dev in ip_devs:
            if 'ha-' in ip_dev.name:
                return ip_dev.name

    def router_is_master_or_slave(self, device_name, namespace):
        try:
            device = ip_lib.IPDevice(device_name, namespace=namespace)
            inc = 0
            device_ip_cidrs = [ip['cidr'] for ip in device.addr.list()]
            for ip_cidr in device_ip_cidrs:
                ipseg = ip_cidr.strip().split('.')
                if len(ipseg) == 4:
                    if ipseg[0] == '169' and ipseg[1] == '254':
                        inc += 1
                else:
                    # to do ipv6
                    continue
                LOG.debug('parsing ha ip_cidr=%s inc=%s', ip_cidr, inc)
            if inc == 2:
                return 'master'

        except RuntimeError:
            return 'slave'
        else:
            return 'slave'

    def router_is_active_standby(self, role):
        if role == 'master':
            return 'active'
        elif role == 'slave':
            return 'standby'
        else:
            return 'error'

    def get_cur_time(self):
        now_time = datetime.datetime.now()
        now = str(now_time.year) + '-' + str(now_time.month) + '-' + \
              str(now_time.day) + '  ' + str(now_time.hour) + ':' + \
              str(now_time.minute) + ':' + str(now_time.second)
        return now

    def get_linux_time(self):
        return time.time()

    def monitor_resource_router(self, router_cnt_log, producer_dict):
        LOG.debug('-----Entry collect router-----')
        router_last_report=123
        router_ns = set()
        router_counter = []
        router_counter_local = []
        try:
            now_time1 = datetime.datetime.now()
            cmd = '/usr/sbin/ip netns | grep qrouter'
            ret_list = self.monitorutils.monitor_util_cmd_execute_list(cmd)

            now_time2 = datetime.datetime.now()

            if len(ret_list) == 0:
                LOG.warrning("collecting router but not found any router...")
                return
            else:
                LOG.info('\n eslaped:%s ret_list=%s ', now_time2 - now_time1, ret_list)

            router_set = set(ret_list)
            for ns in router_set:
                if len(ns) >= meter_const.VROUTER_NS_LEN and meter_const.ROUTER_LABLE in ns:
                    ns = ns.split(' ')[0]
                    router_ns.add(ns)

                    # get connections
                    conn = self.get_router_connections(ns)

                    # get role
                    ha_dev_name = self.get_ha_interface_in_namespace(ns)
                    role = self.router_is_master_or_slave(ha_dev_name, ns)
                    LOG.debug('\n ns=%s, conn=%s, ha_dev_name=%s, role:%s', ns, conn, ha_dev_name, role)
                    ns_uuid = ns[(meter_const.ROUTER_LABLE_LEN + 1):]

                    router_dict = {'timestamp': self.get_linux_time(),
                                   'role': role,
                                   'status': self.router_is_active_standby(role),  # todo change query db
                                   'connections': conn,
                                   'uuid': ns_uuid}

                    router_counter.append(router_dict)

                    router_dict_local = {'timestamp': self.get_cur_time(),
                                         'role': role,
                                         'status': self.router_is_active_standby(role),
                                         'connections': conn,
                                         'uuid': ns_uuid}
                    router_counter_local.append(router_dict_local)

                else:
                    LOG.warrning('Invalid router namespace, remove it:%s', ns)
            LOG.debug('-----exit collect router-----')
        except Exception as e:
            LOG.error('analying router namespace failed...%(router_ns)s reason %(except)s', {'router_ns':router_ns,'except':e})
            return

        try:
            router_str = json.dumps(router_counter, ensure_ascii=False, indent=1)
            LOG.debug('===router_str to kafka===:%s', router_str)
            producer_dict['producer_router'].produce(router_str)

            router_str_local = json.dumps(router_counter_local, ensure_ascii=False, indent=1)
            router_cnt_log.logger.info(router_str_local)

        except Exception as e:
            LOG.error('reporting router counter failed...')
            return

    def get_router_connections(self, ns_id):
        cmd = '/usr/sbin/ip netns exec ' + ns_id + \
              ' cat /proc/net/nf_conntrack | wc -l'
        try:
            ret_list = self.monitorutils.monitor_util_cmd_execute_list(cmd)
            x = ret_list[0] if len(ret_list) >= 1 else 0
        except Exception as e:
            LOG.error('reporting router connections failed...reason %(except)s', {'except':e})
            return 0
        return int(x)
