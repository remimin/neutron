import logging
import os
import gzip
import time
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

    def __init__(self, file_name, level='info', when='D', backCount=5,
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

        # file_handler =handlers.TimedRotatingFileHandler(filename=file_name,
        #                                                 when=when,
        #                                                 backupCount=backCount,
        #                                                 encoding='utf-8')
        file_handler = GzipTimedRotatingFileHandler(filename=file_name,
                                                    when=when,
                                                    backCount=backCount)
        file_handler.setFormatter(format_str)

        self.logger.addHandler(stream_handler)
        self.logger.addHandler(file_handler)


class GzipTimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
    def __init__(self, filename, when='D', backCount=5):

        super(GzipTimedRotatingFileHandler, self).__init__(filename,
                                                           when,
                                                           backCount,
                                                           encoding='utf-8',
                                                           delay=False)
        self.maxBytes = 524288000
        self.delay = False
        self.filename = filename

    def shouldRollover(self, record):
        """
        Determine if rollover should occur.

        Basically, see if the supplied record would cause the file to exceed
        the size limit we have.
        """
        if self.stream is None:                 # delay was set...
            self.stream = self._open()
        if self.maxBytes > 0:                   # are we rolling over?
            msg = "%s\n" % self.format(record)
            # due to non-posix-compliant Windows feature
            self.stream.seek(0, 2)
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return 1
        t = int(time.time())
        if t >= self.rolloverAt:
            return 1
        return 0

    def doGzip(self, old_log):
        with open(old_log) as old:
            with gzip.open(old_log + '.gz', 'wb') as comp_log:
                comp_log.writelines(old)
        os.remove(old_log)

    def doRollover(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        currentTime = int(time.time())
        dstNow = time.localtime(currentTime)[-1]
        t = self.rolloverAt - self.interval
        if self.utc:
            timeTuple = time.gmtime(t)
        else:
            timeTuple = time.localtime(t)
            dstThen = timeTuple[-1]
            if dstNow != dstThen:
                if dstNow:
                    addend = 3600
                else:
                    addend = -3600
                timeTuple = time.localtime(t + addend)

        dfn = self.baseFilename + "." + time.strftime(self.suffix, timeTuple)
        file_dir = self.baseFilename[:self.baseFilename.rfind('/')]
        file_name = self.baseFilename[(self.baseFilename.rfind('/')+1):]
        files = os.listdir(file_dir)
        n = 0
        for i in files:
            if file_name in i:
                n = n + 1
        newname = dfn + "_" + str(n+1)
        if os.path.exists(newname):
            os.remove(newname)
        # Issue 18940: A file may not have been created if delay is True.
        if os.path.exists(self.baseFilename):
            os.rename(self.baseFilename, newname)
            self.doGzip(newname)
        if self.backupCount > 0:

            for s in self.getFilesToDelete():
                os.remove(s)
        if not self.delay:
            self.stream = self._open()
        newRolloverAt = self.computeRollover(currentTime)
        while newRolloverAt <= currentTime:
            newRolloverAt = newRolloverAt + self.interval
        #If DST changes and midnight or weekly rollover, adjust for this.
        if (self.when == 'MIDNIGHT' or self.when.startswith('W')) and not self.utc:
            dstAtRollover = time.localtime(newRolloverAt)[-1]
            if dstNow != dstAtRollover:
                if not dstNow:  # DST kicks in before next rollover, so we need to deduct an hour
                    addend = -3600
                else:           # DST bows out before next rollover, so we need to add an hour
                    addend = 3600
                newRolloverAt += addend
        self.rolloverAt = newRolloverAt

