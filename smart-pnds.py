#!/usr/bin/python2 -u
## -*- coding: utf-8 -*-
import sys
import syslog
import itertools
from collections import defaultdict
from pyip import IPInfo
from os.path import realpath,dirname,join,exists

py_pdns = join(dirname(realpath(__file__)), "pdns-remotebackend-python/src")
if exists(py_pdns):
    sys.path.insert(0, py_pdns)
import pdns.remotebackend, pdns.remotebackend.unix

QQWry_DB = join(dirname(realpath(__file__)), 'qqwry.dat')
QQWry = IPInfo(QQWry_DB)
DOMAIN = {}

class StaticDomain(object):

    def __init__(self, qname, default_ttl=300, auth=1):
        self.qname = qname
        self.records = defaultdict(list)

    def add_record(self, qtype, content, ttl=300, auth=1):
        self.records[qtype].append({'qtype': qtype, 'qname': self.qname, 'content': content, 'ttl': ttl, 'auth': auth})

    def query(self, qtype, query_args = None):
        if qtype == 'ANY':
            return list(itertools.chain.from_iterable(self.records.values()))
        else:
            return self.records.get(qtype, list())


class DynamicDomain(StaticDomain):

    def __init__(self, *args, **argkw):
        super(DynamicDomain, self).__init__(*args, **argkw)
        self.dyn_methods = {}

    def add_dyn_record(self, qtype, dyn_content):
        if not callable(dyn_content):
            raise Exception('dyn_content need to be callable')
        self.dyn_methods[qtype] = dyn_content

    def query(self, qtype, query_args):
        for qtype, dyn_content in self.dyn_methods.items():
            self.records[qtype] = \
                    [{'qtype': qtype, 'qname': self.qname, 
                        'content': value, 'ttl':0, 'auth':1} for value in dyn_content(query_args)]
        return super(DynamicDomain, self).query(qtype, query_args)

class ISPSmartDomain(StaticDomain):

    def __init__(self, *args, **argkw):
        super(ISPSmartDomain, self).__init__(*args, **argkw)
        self.isp_a_record = defaultdict(list)
        self.default_isp = ''
        self.isp_keys = None

    def set_default_isp(self, default_isp):
        self.default_isp = default_isp

    def add_isp_a_record(self, isp, ip):
        if isinstance(ip, list) or isinstance(ip, tuple):
            self.isp_a_record[isp].extend([ \
                {'qtype': 'A', 'qname': self.qname, 'content': cnt, 'ttl': 0, 'auth': 1} for cnt in ip ])
        else:
            self.isp_a_record[isp].append({'qtype': 'A', 'qname': self.qname, 'content': ip, 'ttl': 0, 'auth': 1})

    def query(self, qtype, query_args):

        if qtype in ('ANY', 'A'):
            remote = query_args['remote']

            if self.isp_keys is None:
                self.isp_keys = self.isp_a_record.keys()

            location, isp = QQWry.getIPAddr(remote)

            syslog.syslog("IP {0} QQWry: {1}-{2}".format(remote, location.encode('utf-8'), isp.encode('utf-8')))

            for key in self.isp_keys:
                if isp.find(key) != -1:
                    break
            else:
                if self.default_isp == '':
                    key = self.isp_keys[0]
                else:
                    key = self.default_isp

            self.records['A'] = self.isp_a_record.get(key, [])

        return super(ISPSmartDomain, self).query(qtype, query_args)

dom = StaticDomain('cdn.ptsang.net')
dom.add_record('SOA', 'ddns1.appgame.com. wemaster@appgame.com. 2014040985 14400 14400 1209600 300', ttl=3600)
dom.add_record('NS', 'ddns1.appgame.com.', ttl=3600)
dom.add_record('NS', 'ddns2.appgame.com.', ttl=3600)
DOMAIN[dom.qname] = dom

dom = StaticDomain('cdn2.ptsang.net')
dom.add_record('SOA', 'ddns1.appgame.com. wemaster@appgame.com. 2014040985 14400 14400 1209600 300', ttl=3600)
dom.add_record('NS', 'ddns1.appgame.com.', ttl=3600)
dom.add_record('NS', 'ddns2.appgame.com.', ttl=3600)
DOMAIN[dom.qname] = dom

dom = DynamicDomain('01.cdn.ptsang.net')
dom.add_record('SOA', 'ddns1.appgame.com. wemaster@appgame.com. 2014040985 14400 14400 1209600 300', ttl=3600)
dom.add_record('NS', 'ddns1.appgame.com.', ttl=3600)
dom.add_record('NS', 'ddns2.appgame.com.', ttl=3600)
dom.add_dyn_record('TXT', lambda args : [args.get('remote',''), 'Your Query IP is:'])
DOMAIN[dom.qname] = dom

dom = ISPSmartDomain('02.cdn.ptsang.net')
dom.add_record('SOA', 'ddns1.appgame.com. wemaster@appgame.com. 2014040985 14400 14400 1209600 300', ttl=3600)
dom.add_record('NS', 'ddns1.appgame.com.', ttl=3600)
dom.add_record('NS', 'ddns2.appgame.com.', ttl=3600)
dom.add_isp_a_record(u"电信", ('1.2.3.1', '1.2.3.2', '1.2.3.3', '1.2.3.4'))
dom.add_isp_a_record(u"联通", ('2.2.3.1', '2.2.3.2', '2.2.3.3', '2.2.3.4'))
dom.add_isp_a_record(u"移动", ('3.2.3.1', '3.2.3.2', '3.2.3.3', '3.2.3.4'))
dom.set_default_isp(u"电信")
DOMAIN[dom.qname] = dom

class MyHandler(pdns.remotebackend.Handler):

    def do_lookup(self,args):
        self.result = []
        qname = args['qname']
        qtype = args['qtype']

        if qname in DOMAIN:
            dom = DOMAIN[qname]
            self.result = dom.query(qtype, args)

pdns.remotebackend.PipeConnector(MyHandler, {"abi":'pipe', "ttl":0}).run()

