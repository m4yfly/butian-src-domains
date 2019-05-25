import aiohttp
import asyncio
import uvloop
from abc import ABCMeta, abstractclassmethod
from config import USER_AGENT, COROUTINE_NUM, DEFAULT_TIMEOUT
from .logger import logger

headers = {'User-Agent':USER_AGENT} 

'''
request item example:
{'method': 'post', 'url': 'https://www.butian.net/Reward/pub', 'data': {'s': 1, 'p': 2}}
'''
class AsyncGrab(object):
    __metaclass__ = ABCMeta

    def __init__(self, request_list, coroutine_num=COROUTINE_NUM, timeout=DEFAULT_TIMEOUT):
        self.request_list = request_list
        self.coroutine_num = coroutine_num
        self.timeout = timeout
        self.cookies = {}
        self.results = []
    
    def set_cookie(self, cookies):
        self.cookies = cookies

    @abstractclassmethod
    def parse(self, url, status, content):
        pass
    
    async def get_body(self, request_config):
        async with aiohttp.ClientSession(cookies=self.cookies, headers=headers) as session:
            url = request_config['url']
            if 'method' in request_config and request_config['method'] == 'post':
                async with session.post(url, data=request_config['data'], timeout=self.timeout) as resp:
                    content = await resp.text()
                    return url, resp.status, content
            else:
                async with session.get(url, timeout=self.timeout) as resp:
                    content = await resp.text()
                    return url, resp.status, content

    async def handle_tasks(self, task_id, work_queue):
        while not work_queue.empty():
            current_request = await work_queue.get()
            try:
                url, status, content = await self.get_body(current_request)
                if status == 200:
                    self.parse(url, status, content)
                else:
                    logger.warning('AsyncGran request {} with status code {}'.format(url, status))
            except Exception as e:
                logger.error('Error in AsyncGrab for {}'.format(current_request))

    def event_loop(self):
        q = asyncio.Queue()
        for request_item in self.request_list:
            q.put_nowait(request_item)
        loop = uvloop.new_event_loop()
        asyncio.set_event_loop(loop)
        tasks = [self.handle_tasks(task_id, q) for task_id in range(self.coroutine_num)]
        loop.run_until_complete(asyncio.wait(tasks))
        loop.close()
    
    



    