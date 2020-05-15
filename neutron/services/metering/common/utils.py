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
from oslo_log import log as logging
from neutron_lib.utils import helpers


LOG = logging.getLogger(__name__)

class MonitorUtils():
    def __init__(self):
        LOG.debug('MonitorUtils init')

    def monitor_util_cmd_execute_list(self,cmd):
        try:
            cmd_result = subprocess.Popen(cmd, bufsize=40960, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                                          close_fds=True)
            _stdout, _stderr = cmd_result.communicate()
            #LOG.debug('cmd=%s \n stdout=%s ', cmd, _stdout)
            _stdout = helpers.safe_decode_utf8(_stdout)
            _stderr = helpers.safe_decode_utf8(_stderr)
            _stdout = _stdout.strip('\n')

        except RuntimeError:
            LOG.error(_stderr)

        return _stdout.splitlines()


    def monitor_util_cmd_execute_counter(cmd):
        try:
            cmd_result = subprocess.Popen(cmd, bufsize=1024, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                                          close_fds=True)
            _stdout, _stderr = cmd_result.communicate()
            #LOG.debug('cmd=%s \n stdout=%s ', cmd, _stdout)
            _stdout = helpers.safe_decode_utf8(_stdout)
            _stderr = helpers.safe_decode_utf8(_stderr)

        except RuntimeError:
            LOG.error(_stderr)

        return _stdout.splitlines()[0]
