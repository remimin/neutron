# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sys
import eventlet
import time
import collections

from neutron_lib.agent import topics
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.utils import runtime
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_service import periodic_task
from oslo_service import service
from oslo_utils import timeutils

from neutron._i18n import _
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.conf.agent import common as config
from neutron.conf.services import metering_agent
from neutron import manager
from neutron import service as neutron_service
from neutron.services.metering.drivers import utils as driverutils

#import pykafka
from pykafka import KafkaClient
from pykafka import exceptions as kafka_exc

from neutron.services.metering.collection import collect_router
from neutron.services.metering.collection import collect_vpc
from neutron.services.metering.collection import collect_dhcp
from neutron.services.metering.common import log_derorator
from neutron.services.metering.common import exceptions as meter_exception
import json

LOG = logging.getLogger(__name__)


ROUTER_COUNTER_LOG= 'router_counter.log'
FIP_COUNTER_LOG= 'fip_counter.log'
VPC_COUNTER_LOG= 'vpc_counter.log'
DHCPVM_COUNTER_LOG= 'vm_counter.log'

router_cnt_log = log_derorator.MonitorLogger(ROUTER_COUNTER_LOG)
fip_cnt_log = log_derorator.MonitorLogger(FIP_COUNTER_LOG)
vpc_cnt_log = log_derorator.MonitorLogger(VPC_COUNTER_LOG)
dhcpvm_cnt_log = log_derorator.MonitorLogger(DHCPVM_COUNTER_LOG)


class MeteringPluginRpc(object):

    def __init__(self, host):
        # NOTE(yamamoto): super.__init__() call here is not only for
        # aesthetics.  Because of multiple inheritances in MeteringAgent,
        # it's actually necessary to initialize parent classes of
        # manager.Manager correctly.
        super(MeteringPluginRpc, self).__init__(host)
        target = oslo_messaging.Target(topic=topics.METERING_PLUGIN,
                                       version='1.0')
        self.client = n_rpc.get_client(target)

    def _get_sync_data_metering(self, context):
        try:
            cctxt = self.client.prepare()
            return cctxt.call(context, 'get_sync_data_metering',
                              host=self.host)
        except Exception:
            LOG.exception("Failed synchronizing routers")


class MeteringAgent(MeteringPluginRpc, manager.Manager):

    def __init__(self, host, conf=None):
        self.conf = conf or cfg.CONF
        self._load_drivers()
        self.context = context.get_admin_context_without_session()

        self.metering_loop = loopingcall.FixedIntervalLoopingCall(
            self._metering_loop
        )
        self.monitor_router_counter_loop = loopingcall.FixedIntervalLoopingCall(
            self.monitor_router_counter
        )
        self.monitor_vpc_counter_loop = loopingcall.FixedIntervalLoopingCall(
            self.monitor_vpc_counter
        )

        measure_interval = self.conf.measure_interval
        self.last_report = 0
        self.router_last_report = 0
        self.vpc_last_report = 0

        self.metering_loop.start(interval=measure_interval)
        self.monitor_router_counter_loop.start(interval=measure_interval)
        self.monitor_vpc_counter_loop.start(interval=measure_interval)

        self.host = host
        self.initKafa = True
        self.topic_producer_dict = collections.defaultdict(list)

        self.label_tenant_id = {}
        self.label_id_mappingto_title = {}
        self.routers = {}
        self.metering_infos = {}
        super(MeteringAgent, self).__init__(host=host)

    def _load_drivers(self):
        """Loads plugin-driver from configuration."""
        LOG.info("Loading Metering driver %s", self.conf.driver)
        if not self.conf.driver:
            raise SystemExit(_('A metering driver must be specified'))
        self.metering_driver = driverutils.load_metering_driver(self,
                                                                self.conf)

    def after_start(self):
        eventlet.spawn_n(self.monitor_resource(context))


    def _get_client_toKafka(self):
        kafka_dict = {'initSucc':True,
                      'client':''}

        try :

            kafka_host = self.conf.get('kafka_host', None)  # "172.20.90.4:9092"
            monitor_topic_router = self.conf.get('monitor_topic_router', None)  # "NeutronCounter"
            monitor_topic_fip = self.conf.get('monitor_topic_fip', None)  # self.conf.get('monitor_topic_fip', None)
            monitor_topic_vpc = self.conf.get('monitor_topic_vpc', None)  # self.conf.get('monitor_topic_vpc', None)
            monitor_topic_vm_healthchk = self.conf.get('monitor_topic_vm_healthchk',
                                                       None)  # self.conf.get('monitor_topic_vm_healthchk', None)

            LOG.debug('kafaka_host=%s', kafka_host)

            if kafka_host is None or \
                    monitor_topic_fip is None or \
                    monitor_topic_vpc is None or \
                    monitor_topic_vm_healthchk is None:
                LOG.error('Can not get kafka_host or topics from configure ')
                kafka_dict = {'initSucc': False}
                return kafka_dict

            client = KafkaClient(hosts=kafka_host)

            monitor_topic_router = client.topics[monitor_topic_router]
            producer_router = monitor_topic_router.get_producer(sync=True)
            kafka_dict['producer_router'] = producer_router

            monitor_topic_fip = client.topics[monitor_topic_fip]
            producer_fip = monitor_topic_fip.get_producer(sync=True)
            kafka_dict['producer_fip'] = producer_fip

            monitor_topic_vpc = client.topics[monitor_topic_vpc]
            producer_vpc = monitor_topic_vpc.get_producer(sync=True)
            kafka_dict['producer_vpc'] = producer_vpc

            monitor_topic_vm_healthchk = client.topics[monitor_topic_vm_healthchk]
            producer_vm_healthchk = monitor_topic_vm_healthchk.get_producer(sync=True)
            kafka_dict['producer_vm_healthchk'] = producer_vm_healthchk

            kafka_dict['client'] =client

        except kafka_exc.NoBrokersAvailableError as e:
            LOG.warning('The remote kafaka server connect failed.')
            kafka_dict = {'initSucc': False}

        return kafka_dict

    def monitor_resource(self, context):
        pass

    def monitor_router_counter(self):
        if self.initKafa:
            self.topic_producer_dict = self._get_client_toKafka()
            LOG.debug('topic_producer_dict:%s', self.topic_producer_dict)
            if self.topic_producer_dict['initSucc']:
                self.initKafa = False

        ts = timeutils.utcnow_ts()
        delta = ts - self.router_last_report

        report_interval = self.conf.report_interval
        if delta >= report_interval:
            router_inst = collect_router.MonitorRouter()
            router_inst.monitor_resource_router(router_cnt_log, self.topic_producer_dict)

            self.router_last_report = ts
        return


    def monitor_vpc_counter(self):
        if self.initKafa:
            self.topic_producer_dict = self._get_client_toKafka()
            LOG.debug('topic_producer_dict:%s', self.topic_producer_dict)
            if self.topic_producer_dict['initSucc']:
                self.initKafa = False

        ts = timeutils.utcnow_ts()
        delta = ts - self.vpc_last_report

        report_interval = self.conf.report_interval
        if delta >= report_interval:
            vpc_inst = collect_vpc.MonitorVPC()
            vpc_inst.monitor_resource_vpc(vpc_cnt_log, self.topic_producer_dict)

            self.vpc_last_report = ts
        return

    def _metering_notification(self):
        for label_id, info in self.metering_infos.items():
            data = {'label_id': label_id,
                    'tenant_id': self.label_tenant_id.get(label_id),
                    'title': self.label_id_mappingto_title[label_id],
                    'pkts': info['pkts'],
                    'bytes': info['bytes'],
                    'time': info['time'],
                    'first_update': info['first_update'],
                    'last_update': info['last_update'],
                    'timestamp': info['last_update'],
                    'host': self.host}

            LOG.debug("Send metering report: %s", data)
            fip_str = json.dumps(data, ensure_ascii=False, indent=1)
            self.topic_producer_dict['producer_fip'].produce(bytes(fip_str))
            fip_cnt_log.logger.info(fip_str)

            # notifier = n_rpc.get_notifier('metering')
            # notifier.info(self.context, 'l3.meter', data)
            info['pkts'] = 0
            info['bytes'] = 0
            info['time'] = 0

    def _purge_metering_info(self):
        deadline_timestamp = timeutils.utcnow_ts() - self.conf.report_interval
        label_ids = [
            label_id
            for label_id, info in self.metering_infos.items()
            if info['last_update'] < deadline_timestamp]
        for label_id in label_ids:
            del self.metering_infos[label_id]

    def _add_metering_info(self, label_id, pkts, bytes):
        ts = timeutils.utcnow_ts()
        info = self.metering_infos.get(label_id, {'bytes': 0,
                                                  'pkts': 0,
                                                  'time': 0,
                                                  'first_update': ts,
                                                  'last_update': ts})
        info['bytes'] += bytes
        info['pkts'] += pkts
        info['time'] += ts - info['last_update']
        info['last_update'] = ts

        self.metering_infos[label_id] = info

        return info

    def _add_metering_infos(self):
        self.label_tenant_id = {}
        self.label_id_mappingto_title = {}
        for router in self.routers.values():
            tenant_id = router['tenant_id']
            labels = router.get(n_const.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']
                self.label_tenant_id[label_id] = tenant_id
                self.label_id_mappingto_title[label_id] = label['mappingtitle']
        accs = self._get_traffic_counters(self.context, self.routers.values())
        LOG.debug('accs=%s', accs)
        if not accs:
            return

        for label_id, acc in accs.items():
            self._add_metering_info(label_id, acc['pkts'], acc['bytes'])



    def _metering_loop(self):
        if self.initKafa:
            self.topic_producer_dict = self._get_client_toKafka()
            LOG.debug('topic_producer_dict:%s', self.topic_producer_dict)
            if self.topic_producer_dict['initSucc']:
                self.initKafa = False


        self._sync_router_namespaces(self.context, self.routers.values())
        self._add_metering_infos()

        ts = timeutils.utcnow_ts()
        delta = ts - self.last_report

        report_interval = self.conf.report_interval
        if delta >= report_interval:
            self._metering_notification()
            self._purge_metering_info()
            self.last_report = ts

    @runtime.synchronized('metering-agent')
    def _invoke_driver(self, context, meterings, func_name):
        try:
            return getattr(self.metering_driver, func_name)(context, meterings)
        except AttributeError:
            LOG.exception("Driver %(driver)s does not implement %(func)s",
                          {'driver': self.conf.driver,
                           'func': func_name})
        except RuntimeError:
            LOG.exception("Driver %(driver)s:%(func)s runtime error",
                          {'driver': self.conf.driver,
                           'func': func_name})

    @periodic_task.periodic_task(run_immediately=True)
    def _sync_routers_task(self, context):
        routers = self._get_sync_data_metering(self.context)

        routers_on_agent = set(self.routers.keys())
        routers_on_server = set(
            [router['id'] for router in routers] if routers else [])
        for router_id in routers_on_agent - routers_on_server:
            del self.routers[router_id]
            self._invoke_driver(context, router_id, 'remove_router')

        if not routers:
            return
        self._update_routers(context, routers)

    def router_deleted(self, context, router_id):
        self._add_metering_infos()

        if router_id in self.routers:
            del self.routers[router_id]

        return self._invoke_driver(context, router_id,
                                   'remove_router')

    def routers_updated(self, context, routers=None):
        if not routers:
            routers = self._get_sync_data_metering(self.context)
        if not routers:
            return
        self._update_routers(context, routers)

    def _update_routers(self, context, routers):
        for router in routers:
            self.routers[router['id']] = router

        return self._invoke_driver(context, routers,
                                   'update_routers')

    def _get_traffic_counters(self, context, routers):
        LOG.debug("Get router traffic counters")
        return self._invoke_driver(context, routers, 'get_traffic_counters')

    def _sync_router_namespaces(self, context, routers):
        LOG.debug("Sync router namespaces")
        return self._invoke_driver(context, routers, 'sync_router_namespaces')

    def add_metering_label_rule(self, context, routers):
        return self._invoke_driver(context, routers,
                                   'add_metering_label_rule')

    def remove_metering_label_rule(self, context, routers):
        return self._invoke_driver(context, routers,
                                   'remove_metering_label_rule')

    def update_metering_label_rules(self, context, routers):
        LOG.debug("Update metering rules from agent")
        return self._invoke_driver(context, routers,
                                   'update_metering_label_rules')

    def add_metering_label(self, context, routers):
        LOG.debug("Creating a metering label from agent")
        return self._invoke_driver(context, routers,
                                   'add_metering_label')

    def remove_metering_label(self, context, routers):
        self._add_metering_infos()

        LOG.debug("Delete a metering label from agent")
        return self._invoke_driver(context, routers,
                                   'remove_metering_label')


class MeteringAgentWithStateReport(MeteringAgent):

    def __init__(self, host, conf=None):
        super(MeteringAgentWithStateReport, self).__init__(host=host,
                                                           conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.agent_state = {
            'binary': 'neutron-metering-agent',
            'host': host,
            'topic': topics.METERING_AGENT,
            'configurations': {
                'metering_driver': self.conf.driver,
                'measure_interval':
                self.conf.measure_interval,
                'report_interval': self.conf.report_interval
            },
            'start_flag': True,
            'agent_type': constants.AGENT_TYPE_METERING}
        report_interval = cfg.CONF.AGENT.report_interval
        self.use_call = True
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            self.state_rpc.report_state(self.context, self.agent_state,
                                        self.use_call)
            self.agent_state.pop('start_flag', None)
            self.use_call = False
        except AttributeError:
            # This means the server does not support report_state
            LOG.warning("Neutron server does not support state report. "
                        "State report for this agent will be disabled.")
            self.heartbeat.stop()
        except Exception:
            LOG.exception("Failed reporting state!")

    def agent_updated(self, context, payload):
        LOG.info("agent_updated by server side %s!", payload)


def main():
    conf = cfg.CONF
    metering_agent.register_metering_agent_opts()
    config.register_agent_state_opts_helper(conf)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    config.setup_privsep()
    server = neutron_service.Service.create(
        binary='neutron-metering-agent',
        topic=topics.METERING_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='neutron.services.metering.agents.'
                'metering_agent.MeteringAgentWithStateReport')
    service.launch(cfg.CONF, server, restart_method='mutate').wait()
