from libs.targets import update_domains
from libs.subdomain_brute import update_subdomains
from libs.extract import extract_all
from utils.logger import logger

def update_all():
    try:
        update_domains()
        update_subdomains()
        extract_all()
    except Exception:
        logger.error('unexpected error occured when update all')

