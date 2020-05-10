import logging
import os
from logging import handlers
from neutron.services.metering.common import constants as meter_const


class MonitorLogger(object):
    level_relations = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'crit': logging.CRITICAL
    }

    def __init__(self, file_name, level='info', when='H', backCount=5,
                 fmt='%(asctime)s - %(levelname)s: %(message)s'):
        file_exits = os.path.exists(meter_const.METERING_LOG_DIR)
        if not file_exits:
            os.makedirs(meter_const.METERING_LOG_DIR)

        file_name = '{0}/{1}'.format(meter_const.METERING_LOG_DIR,file_name)
        self.logger = logging.getLogger(file_name)
        format_str = logging.Formatter(fmt)
        self.logger.setLevel(self.level_relations.get(level))
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(format_str)

        file_handler =handlers.TimedRotatingFileHandler(filename=file_name,
                                                        when=when,
                                                        backupCount=backCount,
                                                        encoding='utf-8')
        file_handler.setFormatter(format_str)

        self.logger.addHandler(stream_handler)
        self.logger.addHandler(file_handler)


