#!/etc/powerdns/pdns-pyenv/bin/python2 -u
## -*- coding: utf-8 -*-
import sys
import syslog
from collections import defaultdict
from pyip import IPInfo
from os.path import dirname,join,exists
if exists(join(dirname(__file__), "pdns-remotebackend-python/src")):
    sys.path.insert(0, join(dirname(__file__), "pdns-remotebackend-python/src"))

import pdns.remotebackend, pdns.remotebackend.unix

QQWry_DB = join(dirname(__file__), 'qqwry.dat')
QQWry = IPInfo(QQWry_DB)

DOMAIN = \
    {
        'cdn.ptsang.net': defaultdict(list),
        '01.cdn.ptsang.net': defaultdict(list),
    }

rec = DOMAIN['cdn.ptsang.net']
rec['SOA'].append('ddns1.appgame.com. wemaster@appgame.com. 2014040985 14400 14400 1209600 300')
rec['NS'].append('ddns1.appgame.com.')
rec['NS'].append('ddns2.appgame.com.')

rec = DOMAIN['01.cdn.ptsang.net']
rec['SOA'].append('ddns1.appgame.com. wemaster@appgame.com. 2014040985 14400 14400 1209600 300')
rec['NS'].append('ddns1.appgame.com.')
rec['NS'].append('ddns2.appgame.com.')
rec['A'].append('8.8.8.8')
rec['A'].append('8.8.4.4')
rec['TXT'].append(lambda args: "!! REMOTE: {0}".format(args.get('remote', '')))
rec['TXT'].append(lambda args:str(args))
rec['TXT'].append('hahahah ........')


CDN_A_REC = \
    {
        '01.cdn.ptsang.net': defaultdict(list),
    }


a_rec = CDN_A_REC['01.cdn.ptsang.net']
a_rec[u'电信'] = ('1.2.3.1', '1.2.3.2', '1.2.3.3', '1.2.3.4')
a_rec[u'联通'] = ('2.2.3.1', '2.2.3.2', '2.2.3.3', '2.2.3.4')
a_rec[u'移动'] = ('3.2.3.1', '3.2.3.2', '3.2.3.3', '3.2.3.4')



def qqwry_ip_select(remoteip, isps):
    key = u'电信' #default
    c, a = QQWry.getIPAddr(remoteip)

    syslog.syslog("IP %s get wry %s" % (remoteip, a.encode('utf-8')))

    for i in isps:
        if a.find(i) != -1:
            key = i
            break

    syslog.syslog("return: %s" % key.encode('utf-8'))

    return key

class MyHandler(pdns.remotebackend.Handler):

    def do_lookup(self,args):
        #syslog.syslog(str(args))

        self.result = []

        qname = args['qname']
        qtype = args['qtype']
        remote = args['remote']

        if qname in DOMAIN:
            rec = DOMAIN[qname]

            if qname in CDN_A_REC and qtype in ('A', 'ANY'):
                a_rec = CDN_A_REC[qname]
                key = qqwry_ip_select(remote, a_rec.keys())
                rec['A'] = a_rec[key]

            if qtype in rec:
                rval = rec.get(qtype)
                for val in [ v(args) if callable(v) else v for v in rval]:
                    self.result.append(self.record(qname, qtype, val))

            elif qtype == 'ANY':
                for rtype, rval in rec.items():
                    for val in [ v(args) if callable(v) else v for v in rval]:
                        self.result.append(self.record(qname, rtype, val))

pdns.remotebackend.PipeConnector(MyHandler, {"abi":'pipe', "ttl":0}).run()

