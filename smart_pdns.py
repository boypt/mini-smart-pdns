import syslog
import itertools
from collections import defaultdict

class StaticDomain(object):

    def __init__(self, qname, default_ttl=300, auth=1):
        self.qname = qname
        self.records = defaultdict(list)

    def add_record(self, qtype, content, ttl=300, auth=1):
        self.records[qtype].append({'qtype': qtype, 'qname': self.qname, 'content': content, 'ttl': ttl, 'auth': auth})

    def query(self, query_args):
        qtype = query_args['qtype']
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

    def query(self, query_args):
        qtype = query_args['qtype']
        for qtype, dyn_content in self.dyn_methods.items():
            self.records[qtype] = \
                    [{'qtype': qtype, 'qname': self.qname, 
                        'content': value, 'ttl':0, 'auth':1} for value in dyn_content(query_args)]
        return super(DynamicDomain, self).query(query_args)

class ISPSmartDomain(StaticDomain):

    def __init__(self, *args, **argkw):
        super(ISPSmartDomain, self).__init__(*args, **argkw)
        self.isp_a_record = defaultdict(list)
        self.default_isp = ''
        self.isp_keys = None
        from pyip import IPInfo
        from os.path import realpath,dirname,join,exists

        QQWry_DB = join(dirname(realpath(__file__)), 'qqwry.dat')
        self.QQWry = IPInfo(QQWry_DB)

    def set_default_isp(self, default_isp):
        self.default_isp = default_isp

    def add_isp_a_record(self, isp, ip):
        if isinstance(ip, list) or isinstance(ip, tuple):
            self.isp_a_record[isp].extend([ \
                {'qtype': 'A', 'qname': self.qname, 'content': cnt, 'ttl': 0, 'auth': 1} for cnt in ip ])
        else:
            self.isp_a_record[isp].append({'qtype': 'A', 'qname': self.qname, 'content': ip, 'ttl': 0, 'auth': 1})

    def query(self, query_args):
        qtype = query_args['qtype']

        if qtype in ('ANY', 'A'):
            remote = query_args['remote']

            if self.isp_keys is None:
                self.isp_keys = self.isp_a_record.keys()

            location, isp = self.QQWry.getIPAddr(remote)


            for key in self.isp_keys:
                if isp.find(key) != -1:
                    break
            else:
                if self.default_isp == '':
                    key = self.isp_keys[0]
                else:
                    key = self.default_isp

            syslog.syslog(u"IP {0} QQWry: {1}-{2}, select {3}".format(remote, location, isp, key).encode('utf-8'))
            self.records['A'] = self.isp_a_record.get(key, [])

        return super(ISPSmartDomain, self).query(query_args)

