# -*- coding: utf-8 -*-
import os

#mode
MODE = 'release'

#global config
__version__ = '0.0.1'
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.103 Safari/537.36'
BASE_DIR = os.path.dirname(__file__)

#logs config
LOGS_DIR = os.path.join(BASE_DIR, 'files/logs')

#targets config
TARGETS_DIR = os.path.join(BASE_DIR, 'files/targets')

#out config
OUT_DIR = os.path.join(BASE_DIR, 'files/out')

COROUTINE_NUM = 10

DEFAULT_TIMEOUT = 10

BUTIAN_SRC_COOKIES = {
        "PHPSESSID":"your_phpsessid",
        "__DC_gid":"your_gid"
}

#subdomain config
SUBS_DIR = os.path.join(BASE_DIR, 'files/subs')