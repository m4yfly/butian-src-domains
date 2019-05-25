import os
import logging
import colorlog
from logging.handlers import TimedRotatingFileHandler
from config import LOGS_DIR, MODE

class VULN_LEVEL:
    SUCCESS = 9
    INFO = 8
    ERROR = 7
    WARNING = 6
    DEBUG = 5

#add custom level in this class
class VulnLogger(logging.Logger):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logging.addLevelName(VULN_LEVEL.DEBUG, '[~]')
        logging.addLevelName(VULN_LEVEL.WARNING, '[!]')
        logging.addLevelName(VULN_LEVEL.ERROR, '[-]')
        logging.addLevelName(VULN_LEVEL.INFO, '[*]')
        logging.addLevelName(VULN_LEVEL.SUCCESS, '[+]')

    def debug(self, msg, *args, **kwargs):
        if self.isEnabledFor(VULN_LEVEL.DEBUG):
            self._log(VULN_LEVEL.DEBUG, msg, args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        if self.isEnabledFor(VULN_LEVEL.WARNING):
            self._log(VULN_LEVEL.WARNING, msg, args, **kwargs)

    def error(self, msg, *args, **kwargs):
        if self.isEnabledFor(VULN_LEVEL.ERROR):
            if MODE == 'dev' and 'exc_info' not in kwargs:
                kwargs['exc_info']=True
            self._log(VULN_LEVEL.ERROR, msg, args, **kwargs)

    def info(self, msg, *args, **kwargs):
        if self.isEnabledFor(VULN_LEVEL.INFO):
            self._log(VULN_LEVEL.INFO, msg, args, **kwargs)

    def success(self, msg, *args, **kwargs):
        if self.isEnabledFor(VULN_LEVEL.SUCCESS):
            self._log(VULN_LEVEL.SUCCESS, msg, args, **kwargs)

logging.setLoggerClass(VulnLogger)
logger = logging.getLogger('vuln_logger')

#set log path
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)
scanner_log_path = os.path.join(LOGS_DIR, 'src-domains.log')

#set logger handler
stream_handler = logging.StreamHandler()
file_handler = TimedRotatingFileHandler(scanner_log_path,"D",1)

logger.setLevel(VULN_LEVEL.DEBUG)

stream_formatter = colorlog.ColoredFormatter(
    '%(log_color)s%(levelname)s %(message)s%(reset)s',
    datefmt=None,
    reset=True,
    log_colors={
        '[~]': 'blue',
        '[*]': 'green',
        '[!]': 'yellow',
        '[-]': 'red',
        '[+]': 'white',
    },
    secondary_log_colors={},
    style='%'
)

file_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
stream_handler.setFormatter(stream_formatter)
file_handler.setFormatter(file_formatter)

logger.addHandler(stream_handler)
logger.addHandler(file_handler)