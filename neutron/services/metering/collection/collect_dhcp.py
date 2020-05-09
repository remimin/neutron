# -*- coding: utf-8 -*-
import subprocess
import os
import eventlet
import re
import socket
import json
import io
import time
from oslo_config import cfg
from oslo_log import log as logging

from neutron_lib.utils import helpers

LOG = logging.getLogger(__name__)


class MonitorDhcp(object):
    def __init__(self):
        LOG.info('MonitorDhcp init')

    def monitor_resource_compute(self, monitor_log, producer_dict):
        LOG.info('-----Entry collect dhcp-----')
        try:
            # pool_ping = eventlet.GreenPool()
            dhcp_file_dir = '/var/lib/neutron/dhcp/'
            namespaces = os.listdir(dhcp_file_dir)
            hostname = socket.gethostname()
            dhcp_data = []
            dhcp_datas = []
            if namespaces:
                for ns_id in namespaces:
                    opt_file = dhcp_file_dir + ns_id + '/opts'
                    with open(opt_file, 'r') as optfile:
                        for line in optfile.readlines():
                            if "option:classless-static-route" in line:
                                line = line.split(',')
                                #LOG.info('-------line %s', line)
                                source_ip = line[line.index('169.254.169.254/32') + 1]
                                dhcp_data.append({'timestamp': time.time(),
                                                  'source_ip': source_ip,
                                                  'hostname': hostname,
                                                  'namspace': ns_id})
                    ns_name = str('qdhcp-' + ns_id)
                    cmd = '/usr/sbin/ip netns exec ' + ns_name + \
                          ' fping -f ' + dhcp_file_dir + ns_id + '/addn_hosts'
                    fping_result = self._execute_cmd_list(cmd)
                    for res in fping_result:
                        vm_ip = res.split(' ')[0]
                        ping_res = res.split(' ')[-1]
                        dhcp_dict = {'vm_ip': vm_ip,
                                     'ping_result': ping_res,
                                     }
                        dhcp_data.append(dhcp_dict)
                    dhcp_datas.append(dhcp_data)
        except Exception as e:
            LOG.error("collecting resource compute failed.")

        try:
            dhcp_str = json.dumps(dhcp_datas, ensure_ascii=False, indent=1)
            #LOG.info('=====dhcp_str %s', dhcp_str)
            producer_dict['monitor_topic_vm_healthchk'].produce(dhcp_str)
            monitor_log.logger.info('dhcp_compute %s', dhcp_str)
        except Exception as e:
            LOG.error("reporting dhcp namespace ping host failed...")
            return

    def _execute_cmd_list(self, cmd):
        LOG.info('----_execute_cmd_list %s', cmd)
        try:
            cmd_result = subprocess.Popen(cmd,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          shell=True,
                                          close_fds=True)
            ping, stderr = cmd_result.communicate()
            LOG.info('----ping %s', ping)
            ping = ping.splitlines()
        except RuntimeError:
            LOG.error(stderr)
        return ping
