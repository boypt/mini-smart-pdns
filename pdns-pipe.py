#!/usr/bin/python3 -u
## -*- coding: utf-8 -*-
import sys
from os.path import realpath,dirname,join,exists

py_pdns = join(dirname(realpath(__file__)), "pdns-remotebackend-python/src")
if exists(py_pdns):
    sys.path.insert(0, py_pdns)

import pdns.remotebackend, pdns.remotebackend.unix
from smart_pdns import StaticDomain,DynamicDomain,ISPSmartDomain

DOMAIN = {}

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
dom.add_record('A', '1.2.4.8', ttl=300)
dom.add_record('A', '210.2.4.8', ttl=300)
dom.add_dyn_record('TXT', lambda args : [args.get('remote',''), 'Your Query IP is:'])
DOMAIN[dom.qname] = dom

dom = ISPSmartDomain('02.cdn.ptsang.net')
dom.add_record('SOA', 'ddns1.appgame.com. wemaster@appgame.com. 2014040985 14400 14400 1209600 300', ttl=3600)
dom.add_record('NS', 'ddns1.appgame.com.', ttl=3600)
dom.add_record('NS', 'ddns2.appgame.com.', ttl=3600)
dom.add_isp_a_record("电信", ('1.2.3.1', '1.2.3.2', '1.2.3.3', '1.2.3.4'))
dom.add_isp_a_record("联通", ('2.2.3.1', '2.2.3.2', '2.2.3.3', '2.2.3.4'))
dom.add_isp_a_record("移动", ('3.2.3.1', '3.2.3.2', '3.2.3.3', '3.2.3.4'))
dom.set_default_isp("电信")
DOMAIN[dom.qname] = dom

class MyHandler(pdns.remotebackend.Handler):

    def do_lookup(self,args):
        self.result = []
        qname = args['qname']
        qtype = args['qtype']

        if qname in DOMAIN:
            dom = DOMAIN[qname]
            self.result = dom.query(args)

pdns.remotebackend.PipeConnector(MyHandler, {"abi":'pipe', "ttl":0}).run()

