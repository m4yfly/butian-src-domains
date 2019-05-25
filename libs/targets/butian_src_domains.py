# -*- coding: utf-8 -*-
import requests
import json
import os
import re
from utils import ColorTqdm
from config import BUTIAN_SRC_COOKIES, TARGETS_DIR, DEFAULT_TIMEOUT
from utils.base import AsyncGrab
from bs4 import BeautifulSoup
from utils.logger import logger


class ButianCompanyDetailGrab(AsyncGrab):

    def parse(self, url, status, content):
        soup = BeautifulSoup(content,'html.parser')
        company_input = soup.find('input',attrs={'name':'company_name'})
        if not company_input:
            if '请登录之后再提交' in content:
                logger.error('未设置有效的cookie')
                exit(0)
            logger.warning('drop domain with error content in {}'.format(url))
            return
        company_name = company_input['value']
        host = soup.find('input',attrs={'name':'host'})['value']
        if company_name and host:
            result = {}
            result['domain'] = host
            result['name'] = company_name
            result['url'] = url
            self.results.append(result)
            logger.debug('get new domain detail success:{}'.format(result))
        else:
            if company_name:
                logger.warning('drop domain with black host:{}'.format(company_name))
            else:
                logger.warning('drop domain with black host in {}'.format(url))


domain_info_url = 'https://www.butian.net/Reward/pub'
domain_detail_url = 'https://www.butian.net/Loo/submit?cid='
domains_path = os.path.join(TARGETS_DIR, 'butian_src_domains.txt')

def loads_butian_domains():
    domain_dict = {}
    id_reg_obj = re.compile('cid=([\d]+)')
    with open(domains_path, 'r') as f:
        line_content = f.readline().strip()
        while line_content:
            domain_item = json.loads(line_content)
            reg_result = id_reg_obj.findall(domain_item['url'])
            if reg_result:
                company_id = reg_result[0]
            else:
                logger.warning('Error url when loads butian domains with {}'.format(line_content))
            domain_dict[company_id] = domain_item
            line_content = f.readline().strip()
    logger.debug('load {} domains from butian_src_domains.txt'.format(len(domain_dict)))
    return domain_dict

def update_butian_src_domains(update_all=False):
    domain_dict = loads_butian_domains()
    domain_first_content = requests.post(domain_info_url,{'s':1, 'p':1}, timeout=DEFAULT_TIMEOUT)
    page_count = json.loads(domain_first_content.content.decode())['data']['count']
    
    logger.debug('start to get {} company pages'.format(page_count))

    pbar = ColorTqdm(total=page_count)

    company_id_list = []
    finish_get_page = False
    for i in range(page_count):
        current_page_num = i + 1
        domain_content = requests.post(domain_info_url,{'s':1, 'p':current_page_num}, timeout=DEFAULT_TIMEOUT)
        json_content = json.loads(domain_content.content.decode())
        company_list = json_content['data']['list']

        #update progress
        pbar.update(1)

        for company_item in company_list:
            company_id = company_item['company_id']

            #when update all, all company id in list
            #when not, only new company id add to list
            if not update_all and company_id in domain_dict:
                finish_get_page = True
                logger.debug('company_id found in dict, skip after')
                break
            else:
                company_id_list.append(company_id)
        if finish_get_page:
            break
    pbar.close()

    result_list = []
    #need get detail to add to domains dict
    need_get_list = []

    #only add by new company id
    if not update_all:
        for company_id in domain_dict:
            result_list.append(domain_dict[company_id])
        for company_id in company_id_list:
            if company_id not in domain_dict:
                need_get_list.append(company_id)
    #update all by all company id
    else:
        for company_id in company_id_list:
            if company_id in domain_dict:
                result_list.append(domain_dict[company_id])
            else:
                need_get_list.append(company_id)

    detail_request_list = []
    logger.debug('start to request new {} domains detail'.format(len(need_get_list)))
    try:
        for id in need_get_list:
            request_config = {}
            request_config['method'] = 'get'
            request_config['url'] = domain_detail_url + id
            detail_request_list.append(request_config)
        butian_company_detail_grab = ButianCompanyDetailGrab(detail_request_list)
        butian_company_detail_grab.set_cookie(BUTIAN_SRC_COOKIES)
        butian_company_detail_grab.event_loop()
        company_detail_list = butian_company_detail_grab.results
    except Exception:
        logger.error('request domain details faild in butian src, may cookies invalid')
    else:
        logger.info('add {} new domains from butian src'.format(len(company_detail_list)))
    result_list.extend(company_detail_list)
    with open(domains_path,'w+') as f:
        for detail in result_list:
            f.write(json.dumps(detail, ensure_ascii=False)+'\n')
    logger.debug('save {} domains to butian_src_domains.txt'.format(len(result_list)))