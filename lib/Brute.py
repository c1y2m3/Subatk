#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
    subDomainsBrute 1.2
    A simple and fast sub domains brute tool for pentesters
    my[at]lijiejie.com (http://www.lijiejie.com)
"""

import multiprocessing
import warnings
warnings.simplefilter("ignore", category=UserWarning)
import gevent
from gevent import monkey
monkey.patch_all(thread=False, socket=False)
from gevent.queue import PriorityQueue
from gevent.lock import RLock
import re
import sys
import dns.resolver
import time
import signal
import glob
import os
from gevent.pool import Pool
import dns.resolver



""" getTerminalSize()
 - get width and height of console
 - works on linux,os x,windows,cygwin(windows)
"""

__all__ = ['getTerminalSize']

def _getTerminalSize_windows():
    res = None
    try:
        from ctypes import windll, create_string_buffer

        # stdin handle is -10
        # stdout handle is -11
        # stderr handle is -12

        h = windll.kernel32.GetStdHandle(-12)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
    except:
        return None
    if res:
        import struct
        (bufx, bufy, curx, cury, wattr,
         left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
        sizex = right - left + 1
        sizey = bottom - top + 1
        return sizex, sizey
    else:
        return None

def _getTerminalSize_tput():
    # get terminal width
    # src: http://stackoverflow.com/questions/263890/how-do-i-find-the-width-height-of-a-terminal-window
    try:
        import subprocess
        proc = subprocess.Popen(["tput", "cols"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = proc.communicate(input=None)
        cols = int(output[0])
        proc = subprocess.Popen(["tput", "lines"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = proc.communicate(input=None)
        rows = int(output[0])
        return (cols, rows)
    except:
        return None



def _getTerminalSize_linux():
    def ioctl_GWINSZ(fd):
        try:
            import fcntl, termios, struct, os
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
        except:
            return None
        return cr

    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass
    if not cr:
        try:
            env = os.environ
            cr = (env['LINES'], env['COLUMNS'])
        except:
            return None
    return int(cr[1]), int(cr[0])



def getTerminalSize():
    import platform
    current_os = platform.system()
    tuple_xy = None
    if current_os == 'Windows':
        tuple_xy = _getTerminalSize_windows()
        if tuple_xy is None:
            tuple_xy = _getTerminalSize_tput()
            # needed for window's python in cygwin's xterm!
    if current_os == 'Linux' or current_os == 'Darwin' or current_os.startswith('CYGWIN'):
        tuple_xy = _getTerminalSize_linux()
    if tuple_xy is None:
        tuple_xy = (80, 25)  # default value
    return tuple_xy

console_width = getTerminalSize()[0] - 2


def is_intranet(ip):
    ret = ip.split('.')
    if len(ret) != 4:
        return True
    if ret[0] == '10':
        return True
    if ret[0] == '172' and 16 <= int(ret[1]) <= 31:
        return True
    if ret[0] == '192' and ret[1] == '168':
        return True
    return False


def print_msg(msg=None, left_align=True, line_feed=False):
    if left_align:
        sys.stdout.write('\r' + msg + ' ' * (console_width - len(msg)))
    else:  # right align
        sys.stdout.write('\r' + ' ' * (console_width - len(msg)) + msg)
    if line_feed:
        sys.stdout.write('\n')
    sys.stdout.flush()


def test_server(server, dns_servers):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.lifetime = resolver.timeout = 5.0
    try:
        resolver.nameservers = [server]
        answers = resolver.query('public-dns-a.baidu.com')    # an existed domain
        if answers[0].address != '180.76.76.76':
            raise Exception('Incorrect DNS response')
        try:
            resolver.query('test.bad.dns.lijiejie.com')    # non-existed domain
            with open('bad_dns_servers.txt', 'a') as f:
                f.write(server + '\n')
            print_msg('[+] Bad DNS Server found %s' % server)
        except Exception as e:
            dns_servers.append(server)
        # print_msg('[+] Server %s < OK >   Found %s' % (server.ljust(16), len(dns_servers)))
    except Exception as e:
        pass
        # print_msg('[+] Server %s <Fail>   Found %s' % (server.ljust(16), len(dns_servers)))


def load_dns_servers():
    # print_msg('[+] Validate DNS servers', line_feed=True)
    dns_servers = []
    pool = Pool(5)
    for server in open('dict/dns_servers.txt').readlines():
        server = server.strip()
        if server and not server.startswith('#'):
            pool.apply_async(test_server, (server, dns_servers))
    pool.join()

    server_count = len(dns_servers)
    # print_msg('\n[+] %s DNS Servers found' % server_count, line_feed=True)
    if server_count == 0:
        print_msg('[ERROR] No valid DNS Server !', line_feed=True)
        sys.exit(-1)
    return dns_servers


def load_next_sub():
    next_subs = []
    _file = 'dict/next_sub_full.txt'
    with open(_file) as f:
        for line in f:
            sub = line.strip()
            if sub and sub not in next_subs:
                tmp_set = {sub}
                while tmp_set:
                    item = tmp_set.pop()
                    if item.find('{alphnum}') >= 0:
                        for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                            tmp_set.add(item.replace('{alphnum}', _letter, 1))
                    elif item.find('{alpha}') >= 0:
                        for _letter in 'abcdefghijklmnopqrstuvwxyz':
                            tmp_set.add(item.replace('{alpha}', _letter, 1))
                    elif item.find('{num}') >= 0:
                        for _letter in '0123456789':
                            tmp_set.add(item.replace('{num}', _letter, 1))
                    elif item not in next_subs:
                        next_subs.append(item)
    return next_subs


def get_out_file_name(target):

    _name = os.path.basename('subnames.txt').replace('subnames', '')
    if _name != '.txt':
        _name = '_' + _name
    outfile = target + _name
    return outfile


def user_abort(sig, frame):
    exit(-1)



class SubNameBrute(object):
    def __init__(self, *params):
        self.domain,self.process_num, self.dns_servers, self.next_subs, \
            self.scan_count, self.found_count, self.queue_size_array, tmp_dir = params
        self.dns_count = len(self.dns_servers)
        self.scan_count_local = 0
        self.found_count_local = 0
        self.resolvers = [dns.resolver.Resolver(configure=False) for _ in range(200)]
        for r in self.resolvers:
            r.lifetime = r.timeout = 10.0
        self.queue = PriorityQueue()
        self.priority = 0
        self.ip_dict = {}
        self.found_subs = set()
        self.timeout_subs = {}
        self.count_time = time.time()
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, self.domain, self.process_num), 'w')
        self.normal_names_set = set()
        self.load_sub_names()
        self.lock = RLock()
        self.i = False

    def load_sub_names(self):
        normal_lines = []
        wildcard_lines = []
        wildcard_set = set()
        regex_list = []
        lines = set()
        with open(get_sub_file_path()) as inFile:
            for line in inFile.xreadlines():
                sub = line.strip()
                if not sub or sub in lines:
                    continue
                lines.add(sub)

                brace_count = sub.count('{')
                if brace_count > 0:
                    wildcard_lines.append((brace_count, sub))
                    sub = sub.replace('{alphnum}', '[a-z0-9]')
                    sub = sub.replace('{alpha}', '[a-z]')
                    sub = sub.replace('{num}', '[0-9]')
                    if sub not in wildcard_set:
                        wildcard_set.add(sub)
                        regex_list.append('^' + sub + '$')
                else:
                    normal_lines.append(sub)
                    self.normal_names_set.add(sub)

        if regex_list:
            pattern = '|'.join(regex_list)
            _regex = re.compile(pattern)
            for line in normal_lines:
                if _regex.search(line):
                    normal_lines.remove(line)

        for _ in normal_lines[self.process_num::6]:
            self.queue.put((0, _))    # priority set to 0
        for _ in wildcard_lines[self.process_num::6]:
            self.queue.put(_)

    def scan(self, j):
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]] + self.dns_servers

        while True:
            try:
                self.lock.acquire()
                if time.time() - self.count_time > 1.0:
                    self.scan_count.value += self.scan_count_local
                    self.scan_count_local = 0
                    self.queue_size_array[self.process_num] = self.queue.qsize()
                    if self.found_count_local:
                        self.found_count.value += self.found_count_local
                        self.found_count_local = 0
                    self.count_time = time.time()
                self.lock.release()
                brace_count, sub = self.queue.get(timeout=3.0)
                if brace_count > 0:
                    brace_count -= 1
                    if sub.find('{next_sub}') >= 0:
                        for _ in self.next_subs:
                            self.queue.put((0, sub.replace('{next_sub}', _)))
                    if sub.find('{alphnum}') >= 0:
                        for _ in 'abcdefghijklmnopqrstuvwxyz0123456789':
                            self.queue.put((brace_count, sub.replace('{alphnum}', _, 1)))
                    elif sub.find('{alpha}') >= 0:
                        for _ in 'abcdefghijklmnopqrstuvwxyz':
                            self.queue.put((brace_count, sub.replace('{alpha}', _, 1)))
                    elif sub.find('{num}') >= 0:
                        for _ in '0123456789':
                            self.queue.put((brace_count, sub.replace('{num}', _, 1)))
                    continue
            except gevent.queue.Empty as e:
                break

            try:

                if sub in self.found_subs:
                    continue

                self.scan_count_local += 1
                cur_domain = sub + '.' + self.domain
                answers = self.resolvers[j].query(cur_domain)

                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.address for answer in answers]))
                    if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '0.0.0.1']:
                        continue
                    if self.i and is_intranet(answers[0].address):
                        continue

                    try:
                        self.scan_count_local += 1
                        answers = self.resolvers[j].query(cur_domain, 'cname')
                        cname = answers[0].target.to_unicode().rstrip('.')
                        if cname.endswith(self.domain) and cname not in self.found_subs:
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]    # new sub
                            if cname_sub not in self.normal_names_set:
                                self.found_subs.add(cname)
                                self.queue.put((0, cname_sub))
                    except Exception as e:
                        pass

                    first_level_sub = sub.split('.')[-1]
                    if (first_level_sub, ips) not in self.ip_dict:
                        self.ip_dict[(first_level_sub, ips)] = 1
                    else:
                        self.ip_dict[(first_level_sub, ips)] += 1
                        if self.ip_dict[(first_level_sub, ips)] > 30:
                            continue

                    self.found_count_local += 1

                    self.outfile.write(cur_domain.ljust(30) + '\t' + ips + '\n')
                    self.outfile.flush()
                    try:
                        self.scan_count_local += 1
                        self.resolvers[j].query('lijiejie-test-not-existed.' + cur_domain)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                        if self.queue.qsize() < 10000:
                            for _ in self.next_subs:
                                self.queue.put((0, _ + '.' + sub))
                        else:
                            self.queue.put((1, '{next_sub}.' + sub))
                    except Exception as e:
                        pass

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                pass
            except dns.resolver.NoNameservers as e:
                self.queue.put((0, sub))    # Retry
            except dns.exception.Timeout as e:
                self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                if self.timeout_subs[sub] <= 2:
                    self.queue.put((0, sub))    # Retry
            except Exception as e:
                import traceback
                traceback.print_exc()
                with open('errors.log', 'a') as errFile:
                    errFile.write('[%s] %s\n' % (type(e), str(e)))

    def run(self):
        threads = [gevent.spawn(self.scan, i) for i in range(200)]
        gevent.joinall(threads)


def run_process(*params):
    signal.signal(signal.SIGINT, user_abort)
    s = SubNameBrute(*params)
    s.run()


def wildcard_test(domain, level=1):
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = dns_servers
        answers = r.query('lijiejie-not-existed-test.%s' % domain)
        ips = ', '.join(sorted([answer.address for answer in answers]))
        if level == 1:
            print 'any-sub.%s\t%s' % (domain.ljust(30), ips)
            wildcard_test('any-sub.%s' % domain, 2)
        elif level == 2:
            exit(0)
    except Exception as e:
        return domain


# check file existence
def get_sub_file_path():
    path = 'dict/subnames_full.txt'
    return path

def run(host):

    # make tmp dirs
    tmp_dir = 'tmp/%s_%s' % (host, int(time.time()))
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    subdomains = []
    multiprocessing.freeze_support()
    dns_servers = load_dns_servers()
    next_subs = load_next_sub()
    scan_count = multiprocessing.Value('i', 0)
    found_count = multiprocessing.Value('i', 0)
    queue_size_array = multiprocessing.Array('i', 6)

    try:
        # print '[+] Run wildcard test'
        domain = wildcard_test(host)
        # print '[+] Start %s scan process' % 6
        # print '[+] Please wait while scanning ... \n'
        start_time = time.time()
        all_process = []
        for process_num in range(6):
            p = multiprocessing.Process(target=run_process,
                                        args=(domain,process_num, dns_servers, next_subs,
                                              scan_count, found_count, queue_size_array, tmp_dir)
                                        )
            all_process.append(p)
            p.start()

        char_set = ['\\', '|', '/', '-']
        count = 0
        while all_process:
            for p in all_process:
                if not p.is_alive():
                    all_process.remove(p)
            groups_count = 0
            for c in queue_size_array:
                groups_count += c
            msg = '[%s] %s found, %s scanned in %.1f seconds, %s groups left' % (
                char_set[count % 4], found_count.value, scan_count.value, time.time() - start_time, groups_count)
            print_msg(msg)
            count += 1
            time.sleep(0.3)
    except KeyboardInterrupt as e:
        print '[ERROR] User aborted the scan!'
        for p in all_process:
            p.terminate()
    except Exception as e:
        print '[ERROR] %s' % str(e)

    out_file_name = get_out_file_name(domain)
    all_domains = set()
    domain_count = 0
    with open(out_file_name, 'w') as f:
        for _file in glob.glob(tmp_dir + '/*.txt'):
            with open(_file, 'r') as tmp_f:
                for domain in tmp_f:
                    if domain not in all_domains:
                        domain_count += 1
                        all_domains.add(domain)       # cname query can result in duplicated domains
                        f.write(domain)

    msg = 'All Done. %s found, %s scanned in %.1f seconds.' % (
        domain_count, scan_count.value, time.time() - start_time)
    print_msg(msg, line_feed=True)
    regex = '(?!3)(?!A)\w*\.%s' % host
    one_page_urls = re.findall(regex, str(all_domains))
    for one_url in one_page_urls:
        subdomains.append(one_url)
    os.remove(out_file_name)
    # print 'Output file is %s' % out_file_name
    return subdomains

