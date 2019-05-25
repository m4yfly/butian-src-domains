import pyfiglet
import os
import json
from config import __version__, TARGETS_DIR
from tqdm import tqdm
from colorama import Fore
from .logger import logger

#custom colorfun tqdm
class ColorTqdm(tqdm):
    def __init__(self, *args, **kwargs):
        if 'bar_format' not in kwargs:
            kwargs['bar_format'] = "%s{l_bar}%s{bar}%s{r_bar}%s" % (Fore.YELLOW, Fore.YELLOW, Fore.YELLOW, Fore.RESET)
        super().__init__(*args, **kwargs)

def singleton(cls, *args, **kw):
    instance={}
    def _singleton():
        if cls not in instance:
            instance[cls]=cls(*args, **kw)
        return instance[cls]
    return _singleton

def banner():
    banner_txt = 'butian-src-domains'
    banner_art = pyfiglet.figlet_format('src-domains')
    banner_art += '# src-domains @version: {}'.format(__version__)
    print('{}{}{}'.format(Fore.CYAN, banner_art, Fore.RESET))

def load_all_targets():
    target_list = []
    target_file_list = os.listdir(TARGETS_DIR)
    try:
        for tf in target_file_list:
            if tf.endswith('.txt'):
                tf_path = os.path.join(TARGETS_DIR, tf)
                with open(tf_path,'r') as f:
                    for line in f:
                        target_list.append(json.loads(line.strip()))
                logger.debug('load {} success'.format(tf))
        logger.debug('load all {} targets success'.format(len(target_list)))
    except Exception:
        logger.error('Error occured when load all targets')
    return target_list

