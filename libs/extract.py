import socket
import os
import json
import traceback
from urllib import parse
from queue import Queue
from threading import Thread
import threading
from config import SUBS_DIR, OUT_DIR
from utils.logger import logger
from utils import ColorTqdm

raw_target_path = os.path.join(SUBS_DIR,'target_with_subdomains.txt')
targets_path = os.path.join(OUT_DIR, 'targets.txt')
ips_path = os.path.join(OUT_DIR, 'ips.txt')
domains_path = os.path.join(OUT_DIR, 'domains.txt')

thread_num = 100

raw_target_queue = Queue()
domains_result = Queue()
ips_result = Queue()
targets_result = Queue()

socket.setdefaulttimeout(5)
pbar = None

def fill_queue():
    with open(raw_target_path,'r') as f:
        line = f.readline().strip()
        while line:
            item = json.loads(line)
            raw_target_queue.put(item)
            line = f.readline().strip()
    global pbar
    pbar = ColorTqdm(total=raw_target_queue.qsize())

def get_ip():
    while True:
        try:
            raw_target_item = raw_target_queue.get()
            raw_target_domain_ip_map = {}
            raw_target_domain_list = []
            raw_target_ip_list = []
            # extract domains
            main_domain = raw_target_item['domain']
            if main_domain.startswith('http://') or main_domain.startswith('https://'):
                if main_domain not in raw_target_domain_list:
                    raw_target_domain_list.append(main_domain)
            else:
                main_domain = 'http://' + main_domain
                if main_domain not in raw_target_domain_list:
                    raw_target_domain_list.append(main_domain)
            for sub,sub_ips in raw_target_item['subdomains'].items():
                subdomain = 'http://'+sub
                if subdomain not in raw_target_domain_list:
                    raw_target_domain_list.append(subdomain)
                raw_target_domain_ip_map[subdomain] = []
                for ip in sub_ips:
                    if ip not in raw_target_ip_list:
                        raw_target_ip_list.append(ip)
                    if ip not in raw_target_domain_ip_map[subdomain]:
                        raw_target_domain_ip_map[subdomain].append(ip)
            
            # extract ips
            for domain in raw_target_domain_list:
                if domain not in raw_target_domain_ip_map:
                    raw_target_domain_ip_map[domain] = []
                    paresd = parse.urlparse(domain)
                    netloc = paresd[1]
                    ip = socket.gethostbyname(netloc)
                    if ip:
                        if ip not in raw_target_ip_list:
                            raw_target_ip_list.append(ip)
                        raw_target_domain_ip_map[domain].append(ip)
               
            for ip in raw_target_ip_list:
                ips_result.put(ip)
            for domain in raw_target_domain_list:
                domains_result.put(domain)
            item = {}
            item['name'] =  raw_target_item['name']
            item['url'] =  raw_target_item['url']
            item['domain2ip'] =  raw_target_domain_ip_map
            targets_result.put(item)
            
        except socket.gaierror:
            pass
        except Exception:
            logger.warning("Error when get ip:"+netloc)
        finally:
            pbar.update(1)
            raw_target_queue.task_done()

def run():
    for i in range(thread_num):
        worker = Thread(target=get_ip)
        worker.setDaemon(True)
        worker.start()

def save_result():
    ips_list = list(set(list(ips_result.queue)))
    domain_list = list(set(list(domains_result.queue)))

    with open(ips_path,'w+') as df:
        for c in ips_list:
            df.write(c + '\n')
    
    with open(domains_path,'w+') as df:
        for c in domain_list:
            df.write(c + '\n')

    with open(targets_path,'w+') as df:
        for c in targets_result.queue:
            df.write(json.dumps(c, ensure_ascii=False) + '\n')

    logger.info('success save {} ips'.format(len(ips_list)))
    logger.info('success save {} domains'.format(len(domain_list)))
    logger.info('success save {} targets'.format(targets_result.qsize()))

def extract_all():
    logger.debug('begin to extract all')

    fill_queue()
    run()
    raw_target_queue.join()
    if pbar:
        pbar.close()

    logger.debug('finish to extract all')

    save_result()

if __name__ == "__main__":
    extract_all()