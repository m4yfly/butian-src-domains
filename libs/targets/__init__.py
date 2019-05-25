from .butian_src_domains import update_butian_src_domains
from utils.logger import logger
from requests.exceptions import RequestException
from json.decoder import JSONDecodeError

def update_domains(update_all=False):
    logger.debug('start to update domains')
    try:
        update_butian_src_domains(update_all)
    except RequestException:
        logger.error('update failed with bad network, please retry')
    except JSONDecodeError:
        logger.error('update failed with json decode error, please retry')
    except Exception:
        logger.error('unexpect error occured, please retry')
    logger.debug('finish update domains')