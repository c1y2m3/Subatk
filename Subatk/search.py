#! /usr/bin/env python2.7
# -*- coding:UTF-8 -*-

import requests
import mmh3
import shodan
import re
import socket
from urllib.parse import urlparse
import multiprocessing
import random
import time
import threading
import queue
import json
import shlex
import subprocess
import xml.etree.ElementTree as ET
import chardet
import smtplib
from email.mime.text import MIMEText
from selenium import webdriver
import configparser
import urllib3
from smtplib import SMTP_SSL
from random import randint
from . import models
urllib3.disable_warnings()
import base64
from functools import reduce

text = []

G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white

class utility(object):
    def __init__(self,domain,engine_name):
        self.subdomains = []
        self.engine_name = engine_name
        self.print_banner()
        self.session = requests.Session()
        self.domain = domain

    def requests_headers(self):
        '''
        Random UA  for every requests && Use cookie to scan
        '''
        user_agent = [
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1",
            "Mozilla/5.0 (X11; CrOS i686 2268.111.0) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/19.77.34.5 Safari/537.1",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5",
            "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.36 Safari/536.5",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
            "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.0 Safari/536.3",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36"
        ]

        UA = random.choice(user_agent)
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'User-Agent': UA, 'Upgrade-Insecure-Requests': '1', 'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Accept-Encoding': 'gzip, deflate,', 'Accept-Language': 'zh-CN,zh;q=0.8'}
        return headers


    def http_request(self,url):
        '''
        http send request
        :param url:
        :return:
        GET / HTTP/1.1
        '''
        try:
            response = requests.get(url,verify=False,timeout=3.5,headers=self.requests_headers())
            response.encoding = response.apparent_encoding
            return response.text
        except:
            pass

    def get_page(self, num):
        return num + 10

    def should_sleep(self):
        time.sleep(random.randint(3, 4))
        return

    def extract(self,domain):

        if domain.startswith('http'):
             url = domain
        elif self.http_request('https://' + domain):
            url = 'https://' + domain
        elif self.http_request('http://' + domain):
            url = 'http://' + domain
        else:
            url = domain
        return url

    def getip(self,url):
        try:

            ipadder = self.getip_(url)
            cidr = ipadder.split(
                '.')[0] + '.' + ipadder.split('.')[1] + '.' + ipadder.split('.')[2] + '.1/24'
            # self.ipadders.append(cidr)
            return cidr
        except Exception:
            return False

    def getip_(self,url):

        """
        :param url:
        :return:
        """
        try:
            result = urlparse(url)
            if re.findall('[0-9]',result.netloc):
                return result.netloc
            elif re.findall('[0-9]',result.path):
                return result.path
            else:
                myadder = socket.getaddrinfo(result.netloc, None)
                ipadder = (myadder[0][4][0])
                return ipadder
        except Exception:
            return url

    def title(self,url):
        try:
            title = re.findall('<title>(.+?)</title>',str(self.http_request(url)),re.S)
            if title is not None:
                return title[0]
            else:
                return False
        except:
            pass

    def print_banner(self):
        if self.engine_name is not None:
            print (G + "[-] Searching now in %s.." % (self.engine_name) + W)
        else:
            pass

    def check(self):
        """ chlid class should override this function """
        return

    def get_html(self,url):
        # bing 搜索需带上cookies
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
            "accept-language": "zh-CN,zh;q=0.9",
            "alexatoolbar-alx_ns_ph": "AlexaToolbar/alx-4.0.3",
            "cache-control": "max-age=0",
            "upgrade-insecure-requests": "1",
            "cookie": "DUP=Q=axt7L5GANVktBKOinLxGuw2&T=361645079&A=2&IG=8C06CAB921F44B4E8AFF611F53B03799; _EDGE_V=1; MUID=0E843E808BEA618D13AC33FD8A716092; SRCHD=AF=NOFORM; SRCHUID=V=2&GUID=CADDA53D4AD041148FEB9D0BF646063A&dmnchg=1; MUIDB=0E843E808BEA618D13AC33FD8A716092; ISSW=1; ENSEARCH=BENVER=1; SerpPWA=reg=1; _EDGE_S=mkt=zh-cn&ui=zh-cn&SID=252EBA59AC756D480F67B727AD5B6C22; SL_GWPT_Show_Hide_tmp=1; SL_wptGlobTipTmp=1; SRCHUSR=DOB=20190616&T=1560789192000; _FP=hta=on; BPF=X=1; SRCHHPGUSR=CW=1341&CH=293&DPR=1&UTC=480&WTS=63696385992; ipv6=hit=1560792905533&t=4; _SS=SID=252EBA59AC756D480F67B727AD5B6C22&HV=1560790599",
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
        }
        resq = self.session.get(url,verify=False,timeout=5,headers=headers)
        return resq.text if hasattr(resq, "text") else resq.content

    def extract_domains(self, resp):
        try:
            regex = '(?!3)(?!A)\w*\.%s' % self.domain
            # regex = '\w*\.%s' % self.domain
            one_page_urls = re.findall(regex, str(resp))
            for one_url in one_page_urls:
                self.subdomains.append(one_url)
            return self.subdomains
        except Exception:
            pass

    def download(self,filename, datas):
        filename = filename.replace("/", "_") + "_open_.txt"
        with open(filename, "a") as f:
            f.write(str(datas) + "\n")
        f.close()
        return filename

    def config(self,options,string):
        import os
        config = configparser.ConfigParser()
        proDir = os.path.split(os.path.realpath(__file__))[0]
        configPath = os.path.join(proDir, "config.ini")
        config.read(configPath, encoding='GB18030')
        return config.get(options,string)

    def clouder(self,website,domain):

        # 使用webdriver绕过cloudFlare验证
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Chrome(chrome_options=chrome_options)
        driver.delete_all_cookies()
        driver.get(website + domain)
        time.sleep(5)
        resp = (driver.page_source)
        return resp


class enumratorBaseThreaded(multiprocessing.Process, utility):
    def __init__(self, domain,engine_name, q=None, lock=threading.Lock()):
        # subdomains = subdomains or []
        utility.__init__(self,engine_name,domain)
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        return

    def run(self):
        try:
            domain_list = self.check()
            for domain in domain_list:
                self.q.append(domain)
        except:
            pass

class Shodann(enumratorBaseThreaded):
    def __init__(self,domain,q=None):
        # self.key = 'fc1ixJR4fHGzzxWJ4an9iZEKOWO5RORx'
        self.key = self.config(options="API",string="ShodanAPI")
        self.lock = threading.Lock()
        self.engine_name = "Shodan Search"
        self.subdomains = []
        super(Shodann, self).__init__(self.engine_name,domain,q=q)
        self.q = q
        self.url = self.extract(domain)


    def shodan_search(self,search):
        if search is not None:
            print(' Waiting for Shodan search now ' + search)
        api = shodan.Shodan(self.key)
        try:
            result = api.search(search)
            if int(result.get('total', '0')) > 0:
                print("[info] 搜索到{}条结果".format(str(result.get('total', '0'))))
                for i in result.get('matches'):
                    hem = "http"
                    if i.get('ssl', ''):
                        hem = "https"
                    if i.get('port', ''):
                        domain = ("{}://{}:{}".format(hem, i.get('ip_str', ''), str(i.get('port'))))
                    else:
                        domain = ("{}://{}".format(hem, i.get('ip_str', '')))
                    # self.subdomains.append(domain)
                    self.subdomains.append(domain)
            else:
                pass
        except Exception:
            pass


    def deff(self,url):

        favicon = self.http_request(url)
        base64_ = (base64.b64encode(bytes(favicon, 'utf-8')))
        hash = mmh3.hash(base64_)
        return hash


    def shodan_favicon(self,url):

        '''
        http.favicon.hash for shodan api
        :param url:
        :return:
        '''
        rep = self.http_request(url)
        ico = re.findall('[a-zA-z]+://[^\s]*.ico',rep)
        resp = re.findall('(?<=")/\S+.ico',rep)
        log = re.findall('(?<=src=")\S+(?<=png|jpg)',rep)
        if ico:
            return ico[0]
        if resp:
            return resp[0]
        if log:
            return log[0]
        else:
            return

    def shodan_cidr(self):
        pass

    def check(self):
        '''
        start
        :return:
        '''
        try:
            title = self.title(self.url)
            resp = self.shodan_favicon(self.url)
            if resp:
                if resp.startswith('http'):
                    favicon = self.deff(resp)
                elif resp.startswith("//"):
                    favicon = self.deff("http://" + resp.replace('//',''))
                elif resp.startswith(".."):
                    favicon = self.deff(self.url + "/" + resp)
                else:
                    favicon = self.deff(self.url + resp)
            self.shodan_search(search='http.favicon.hash:{hash}'.format(hash=favicon))
            cidr = self.getip(self.url)
            self.shodan_search(search='http.title:{title}'.format(title=title))
            self.shodan_search(search='http.html:"{domain}"'.format(domain=self.domain))
            self.shodan_search(search='net:"{cidr}"'.format(cidr=cidr))
            return self.subdomains
        except Exception:
            pass



class crtsearch(enumratorBaseThreaded):
    def __init__(self,domain,q=None):
        self.domain = domain
        self.url = 'https://crt.sh/?q={}'
        self.q = q
        self.domain_links = set()
        self.result = set()
        self.engine_name = "SSL Certificates"
        super(crtsearch, self).__init__(self.engine_name,domain,q=q)

    def check(self):
        url = self.url.format(self.domain)
        html = self.get_html(url)
        links = re.findall(b'<A href="(\?id=\d.+)">', html)
        for link in links:
            self.domain_links.add('https://crt.sh/' + link.decode())
        for domain_link in self.domain_links:
            try:
                rep = self.get_html(domain_link)
                if b'Subject&nbsp;Alternative&nbsp;Name:&nbsp;' in rep:
                    domains = re.findall(b'DNS:(.*?)<BR>', rep)
                    for domain_ in domains:
                        if self.domain in domain_.decode():
                            self.result.add(domain_.decode().replace('*.', ''))
            except Exception as e:
                pass
        return self.result

class zoomeye(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        self.domain = domain
        self.engine_name = "Zoomeye Search"
        self.API_URL = "https://api.zoomeye.org"
        self.email = self.config(options='AUTH',string='USERNAME')
        self.passwd = self.config(options='AUTH',string='PASSWORD')
        self.platform = "web"
        self.subdomains = []
        self.url = self.extract(domain)
        # self.page_num = 0
        super(zoomeye, self).__init__(self.engine_name, domain, q=q)

    def getRandomUserAgent(self):
        user_agents = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
                       "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
                       "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
                       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
                       "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
                       "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
                       "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
                       "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                       "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
                       "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
                       "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36",
                       "Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.17",
                       "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
                       "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"]
        return user_agents[randint(0, len(user_agents) - 1)]

    def getToken(self):
        USER_DATA = '{"username": ' + '"' + self.email + '"' + \
                    ', "password":  ' + '"' + self.passwd + '"' + '}'
        AUTH = requests.post(self.API_URL + '/user/login', data=USER_DATA)
        if (AUTH.status_code == 403):
            raise KeyError
        return AUTH.json()['access_token']

    def search(self,query):
        if query is not None:
            print(' Waiting for Zoomeye search now ' + query)
        TOKEN = "JWT " + self.getToken()
        HEADERS = {"Authorization": TOKEN, "user-agent": self.getRandomUserAgent()}
        try:
            for page in range(1,6):
                SEARCH = requests.get(self.API_URL + '/' + self.platform + '/search',
                                      headers=HEADERS, params={"query": query, "page": page})
                response = json.loads(SEARCH.text)
                i = 0
                while i < len(response["matches"]):
                    resultItem = response["matches"][i]["site"]
                    # result = response["matches"][i]["ip"][0]
                    self.subdomains.append(resultItem)
                    i += 1
        except IndexError:
            return
        except KeyError:
            quit()

    def check(self):

        title = self.title(self.url)
        self.search(query='site:{www}'.format(www=self.domain))
        if title is not None:
            self.search(query=('keywords:{title}'.format(title=title)))
        # self.search(query='hostname:{}'.format(domain)) # 较大几率存在误报,使用中可注释掉。
        return self.subdomains


class Baidusaerch(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        # self.base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.lock = threading.Lock()
        self.domain  = domain
        self.timeout = 3
        self.query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        self.engine_name = "Baidusaerch"
        self.subdomains = []
        super(Baidusaerch, self).__init__(self.engine_name, domain, q=q)
        self.q = q


    def random_url(self,page_no,query):

        # servers = ['www.baidu.com','61.135.169.121','14.215.177.38','61.135.169.125']
        servers = ['www.baidu.com',]
        baidu_server = random.choice(servers)
        url = 'https://' + baidu_server + '/s?pn={page_no}&wd={query}&oq={query}'\
            .format(page_no=page_no,query=query)
        return url

    def get_sub_domain(self, page_num=0):
        url = self.random_url(query=self.query, page_no=page_num, )
        content = requests.get(url, headers=self.requests_headers()).content
        if 'class="n">下一页' in content.decode():
            new_page_num = page_num + 10
            url = self.random_url(query=self.query, page_no=new_page_num,)
            thread_list = []
            t = threading.Thread(target=self.get_sub_domain, args=(new_page_num,))
            thread_list.append(t)
            for t in thread_list:
                t.start()
            for t in thread_list:
                t.join()

        one_page_urls = self.extract_domains(content)
        return one_page_urls

    def check(self):

        subdomains = self.get_sub_domain()
        return subdomains


class Baiduapi(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        self.domain = domain
        self.url = 'http://ce.baidu.com/index/getRelatedSites?site_address={}'
        self.q = q
        self.engine_name = "Baidu API"
        super(Baiduapi, self).__init__(self.engine_name,domain,q=q)


    def check(self):
        url = self.url.format(self.domain)
        # req = self.http_request(url).json()
        req = requests.get(url).json()
        data = req.get('data')
        for u in data:
            if u.get('domain') != None:
                self.subdomains.append(u.get('domain'))
        return self.subdomains


class Bingsearch(enumratorBaseThreaded):
    def __init__(self,domain,q=None):
        self.domain = domain
        self.query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        self.url = "https://cn.bing.com/search?q={}&ensearch=1&first={}"
        self.q = q
        self.engine_name = "Bingsearch"
        self.limit_num = 300
        super(Bingsearch, self).__init__(self.engine_name,domain,q=q)

    def extract_domains(self,html):

        resq = re.findall("<h2><a.*?href=\"(.*?)\".*?>(.*?)</a></h2>", html)
        for __, _ in resq:
            url = urlparse(__)
            self.subdomains.append(url.netloc)
        return self.subdomains

    def get_sub_domain(self,page_num =0):
        # for page_no in range(0, 200, 10):
        baseurl = self.url.format(self.query,page_num,)
        html = self.get_html(url=baseurl)
        if page_num <= self.limit_num :
            new_page_num = page_num + 10
            url = self.url.format(self.query,new_page_num,)
            thread_list = []
            t = threading.Thread(target=self.get_sub_domain, args=(new_page_num,))
            thread_list.append(t)
            for t in thread_list:
                t.start()
            for t in thread_list:
                t.join()

        one_page_urls = self.extract_domains(html)
        return one_page_urls

    def check(self):
        subdomains = self.get_sub_domain()
        return subdomains


class ip138search(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        self.domain = domain
        self.url = "http://site.ip138.com/{}/domain.htm".format(self.domain)
        self.q = q
        self.engine_name = "ip138search"
        self.page_num = 0
        super(ip138search, self).__init__(self.engine_name,domain,q=q)

    def check(self):
        try:
            # resp = self.get_html(self.url)
            resp = self.http_request(self.url)
            subdomains = self.extract_domains(resp)
            return subdomains
        except Exception:
            pass

class virustotal(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        self.domain = domain
        self.url = "https://www.virustotal.com/ui/domains/{}/subdomains".format(self.domain)
        self.q = q
        self.engine_name = "virustotal"
        self.page_num = 0
        super(virustotal, self).__init__(self.engine_name,domain,q=q)


    def check(self):
        try:
            resp = self.get_html(self.url)
            subdomains = self.extract_domains(resp)
            return subdomains
        except Exception:
            pass

class Google(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        self.domain = domain
        self.q = q
        # self.url = 'https://www.uedbox.com/post/54776/'
        self.engine_name = "Google Search"
        self._server = []
        self.query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        self.extract = 'https://\w+.\w+.\w+/'
        self.search = 'search?q={}&start={}'
        self.limit_num = 300
        super(Google, self).__init__(self.engine_name,domain,q=q)
        self.baseurl = self.random_url()

    def random_url(self):

        _server = ['https://gg.i-research.edu.eu.org/',
                   'https://w.tw.53yu.com/','https://so.bban.fun/','http://p.izhaolei.com/','https://www.kuaimen.bid/']
        for google_server in _server:
            code = self.http_request(google_server)
            if code:
                self._server.append(google_server)
        return random.choice(self._server)


    def get_sub_domain(self,page_num =0):
        url = self.baseurl + self.search.format(self.query,page_num,)
        content = requests.get(url, headers=self.requests_headers()).content
        if page_num <= self.limit_num:
            # if '我们的系统检测到您的计算机网络中存在异常流量' not in content.decode():
            new_page_num = page_num + 10
            url = self.baseurl + self.search.format(self.query,page_num, )
            thread_list = []
            t = threading.Thread(target=self.get_sub_domain, args=(new_page_num,))
            thread_list.append(t)
            for t in thread_list:
                t.start()
            for t in thread_list:
                t.join()
        one_page_urls = self.extract_domains(content)
        return one_page_urls

    def check(self):

        subdomains = self.get_sub_domain()
        return subdomains


class DNSSearch(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        self.domain = domain
        self.q = q
        self.engine_name = "dnssearch"
        self.website = 'https://dns.bufferover.run/dns?q='
        super(DNSSearch, self).__init__(self.engine_name,domain,q=q)

    def check(self):
        try:
            resp = self.clouder(website=self.website,domain=self.domain)
            subdomains = self.extract_domains(resp)
            return subdomains
        except Exception as e:
            print (e)

class threatcrowd(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        self.domain = domain
        self.q = q
        self.engine_name = "threatcrowd"
        self.website = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain='
        super(threatcrowd,self).__init__(self.engine_name,domain,q=q)

    def check(self):
        try:
            resp = self.clouder(website=self.website,domain=self.domain)
            subdomains = self.extract_domains(resp)
            return subdomains
        except Exception as e:
            print (e)

class threatminer(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        self.domain = domain
        self.q = q
        self.engine_name = "threatminer"
        self.website = 'https://www.threatminer.org/getData.php?e=subdomains_container&q={}&t=0&rt=10&p=1'
        super(threatminer,self).__init__(self.engine_name,domain,q=q)

    def check(self):
        try:
            resp = self.get_html(self.website.format(self.domain))
            subdomains = self.extract_domains(resp)
            return subdomains
        except Exception:
            pass

class subDomainsBrute(enumratorBaseThreaded):

    def __init__(self,domain,q=None):
        self.domain = domain
        self.q = q
        self.engine_name = "subDomainsBrute"
        super(subDomainsBrute, self).__init__(self.engine_name,domain,q=q)

    def check(self):
        try:
            from .Brute import run
            subdomains = run(self.domain)
            # subdomains = self.extract_domains(str(resp))
            return subdomains
        except Exception:
            pass

class do_scan(utility):

    def __init__(self, host):
        # threading.Thread.__init__(self)
        utility.__init__(self,engine_name=None,domain='')
        self.queue = queue
        self.host = host
        self.arguments = '-Pn -sS -n --rate=3000 --open --wait=5'
        '''
        修改masscan启动路径
        '''
        # self.masscan_p = 'masscan'
        self.masscan_p = self.config(options='PATH',string='masscan_p')
        self.ports = self.config(options='PORT',string='ports')
        self.dport = []
        # self.lock = threading.Lock()

    def run(self):
        ipadder = self.getip_(self.host)
        h_ = shlex.split(ipadder)
        f_ = shlex.split(self.arguments)
        args = [self.masscan_p, '-oX', '-'] + h_ + \
               ['-p', self.ports] * (self.ports is not None) + f_
        p = subprocess.Popen(args,
                             bufsize=100000,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE
                             )

        _masscan_output, _err = p.communicate()
        try:
            dom = ET.fromstring(_masscan_output)
            for dhost in dom.findall('host'):
                for dport in dhost.findall('ports/port'):
                    port = int(dport.get('portid'))
                    self.dport.append(port)
            if self.dport is not None:
                return self.dport
            else:
                return
        except:
            return

class is_alive(threading.Thread,utility):

    def __init__(self, queue,domain,save,taskid):
        threading.Thread.__init__(self)
        self.queue = queue
        self.save = save
        self.taskid = taskid
        self.domain = domain
        self.now_time = time.strftime('%Y-%m-%d', time.localtime(time.time()))
        self.filename = self.domain + '_' + self.now_time
        self.nums = []
        print('[-] Get site title...')


    def run(self):
        while True:
            domain = self.queue.get()
            try:
                url = self.extract(domain)
                print(url)
                drport = do_scan(url)
                title = self.title(url)
                # resource_list  = [{'url': domain,'title': None,'protocols' :[None]}]
                resource_list = [{'url': url,'title': title,'protocols' :drport.run()}]
                # text = json.dumps(result,encoding=encoding,ensure_ascii=False)
                self.save.append(resource_list)
                models.Message.objects.filter(id=self.taskid).update(openresult=self.save)
            except:
                pass
            self.queue.task_done()

class sendmail(utility):

    def __init__(self,filename,total):
        self.filename = filename[0]
        utility.__init__(self,engine_name=None,domain='')
        self.total = total
        self.msg_from = self.config(options='MAIL',string='MSG_from')
        self.msg_to = self.config(options='MAIL',string='MSG_to')
        self.passward = self.config(options='MAIL',string='MAILPASS')
        self.subject = '任务状态提示——已完成'

    def main(self):
        with open(self.filename,'r+') as f:
            text = f.read()
            content = '<html><body><h2>Hello Sir</h2>''<p>{total}</a>...</p>{text}''</body></html>'.format(total=total,text=text)
        msg = MIMEText(content, 'html', 'utf-8')
        msg['Subject'] = self.subject
        msg['From'] = self.msg_from
        msg['To'] = self.msg_to
        try:
            s = SMTP_SSL('smtp.126.com')
            s.ehlo()
            s.login(self.msg_from, self.passward)
            s.sendmail(self.msg_from, self.msg_to, msg.as_string())
            print(G + '[-] 任务已完成，发送邮件成功,')
        except smtplib.SMTPException as e:
            print (e)
        finally:
            s.close()
