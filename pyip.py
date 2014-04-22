#!/usr/bin/env python
# coding: utf-8
 
# from: http://linuxtoy.org/files/pyip.py
# Blog: http://linuxtoy.org/archives/python-ip.html
# Modified by Demon
# Blog: http://demon.tw/programming/python-qqwry-dat.html
# Modified by adamhj
# Blog: http://adamhj.blogsome.com
 
'''用Python脚本查询纯真IP库
 
QQWry.Dat的格式如下:
 
+----------+
|  文件头  |  (8字节)
+----------+
|  记录区  | （不定长）
+----------+
|  索引区  | （大小由文件头决定）
+----------+
 
文件头：4字节开始索引偏移值+4字节结尾索引偏移值
 
记录区： 每条IP记录格式 ==> IP地址[国家信息][地区信息]
 
   对于国家记录，可以有三种表示方式：
 
       字符串形式(IP记录第5字节不等于0x01和0x02的情况)，
       重定向模式1(第5字节为0x01),则接下来3字节为国家信息存储地的偏移值
       重定向模式(第5字节为0x02),
    
   对于地区记录，可以有两种表示方式： 字符串形式和重定向
 
   最后一条规则：重定向模式1的国家记录后不能跟地区记录
 
索引区： 每条索引记录格式 ==> 4字节起始IP地址 + 3字节指向IP记录的偏移值
 
   索引区的IP和它指向的记录区一条记录中的IP构成一个IP范围。查询信息是这个
   范围内IP的信息
 
'''
 
import sys
import socket
from struct import pack, unpack, unpack_from
 
class IPInfo(object):
    '''QQWry.Dat数据库查询功能集合
    '''
    def __init__(self, dbname):
        ''' 初始化类，读取数据库内容为一个字符串，
        通过开始8字节确定数据库的索引信息'''
         
        self.dbname = dbname
        f = open(dbname, 'rb')
 
        self.img = f.read()
        f.close()
 
        # QQWry.Dat文件的开始8字节是索引信息,前4字节是开始索引的偏移值，
        # 后4字节是结束索引的偏移值。
        (self.firstIndex, self.lastIndex) = unpack_from('<II', self.img)
 
        # 每条索引长7字节，这里得到索引总个数
        self.indexCount = int((self.lastIndex - self.firstIndex) / 7) + 1
     
    index2ip = lambda self,index : unpack_from('<I', self.img, self.firstIndex + index * 7)[0]

    #'''QQWry.Dat中的偏移记录都是3字节，本函数取得3字节的偏移量的常规表示 QQWry.Dat使用“字符串“存储这些值'''
    # little-endian integer
    byte3offset = lambda self,offset : (unpack_from('<I', self.img, offset-1)[0] & 0xffffff00) >> 8
 
    def getAddr(self, offset, addr_count=2):
        ''' read address from offset, addr_count indicate how many addresses(string/pointer to string) 
        should be return.'''
         
        i = 0
        addrs = []
        while i < addr_count:
            i += 1
            byte = self.img[offset]

            if byte == 1:
                # 重定向模式1
                # [IP][0x01][国家和地区信息的绝对偏移地址]
                # 使用接下来的3字节作为偏移量调用字节取得信息
                addrs += self.getAddr(self.byte3offset(offset + 1), 2)
                i += 1  # skip 1 address as we got 2 at a time
                offset += 4     # move to next address(if exists)
            elif byte == 2:
                # 重定向模式2
                # [IP][0x02][国家/地区信息的绝对偏移]
                # 使用国家/地区信息偏移量调用自己取得字符串信息
                addrs += self.getAddr(self.byte3offset(offset + 1), 1)
                offset += 4     # move to next address(if exists)
            else:
                offset2 = self.img.find(0, offset)
                gb2312_str = self.img[offset:offset2]
                try:
                    uni_str = gb2312_str.decode('gb2312')
                except:
                    uni_str = '错误'
                addrs.append(uni_str)
                offset = offset2 + 1

        return addrs
                 
                 
    def getAddrSafe(self, offset, addr_count=2):
        ''' read address from offset, addr_count indicate how many addresses(string/pointer to string) 
        should be return, add excption handleing '''
        err = ('错误', '错误')
        try:
            retval = tuple(self.getAddr(offset, addr_count))
            if len(retval) != 2:
                retval = err
        except:
            retval = err
        return retval
         
 
    def find(self, ip, l, r):
        ''' 使用二分法查找网络字节编码的IP地址的索引记录'''
        if r - l <= 1:
            return l
 
        m = int((l + r) / 2)
        mid_ip = self.index2ip(m)
        return self.find(ip, l, m) if ip < mid_ip else self.find(ip, m, r)

         
    def getIPAddr(self, ip):
        ''' 调用其他函数，取得信息！'''
        # 使用网络字节编码IP地址
        ip = unpack('!I', socket.inet_aton(ip))[0]
        # 使用 self.find 函数查找ip的索引偏移
        i = self.find(ip, 0, self.indexCount - 1)
        # 得到索引记录
        # 索引记录格式是： 前4字节IP信息+3字节指向IP记录信息的偏移量
        o = self.firstIndex + i * 7
        ip2 = self.index2ip(i)

        # check if ip is in range
        if ip >= ip2:
            # 这里就是使用后3字节作为偏移量得到其常规表示（QQWry.Dat用字符串表示值）
            o2 = self.byte3offset(o + 4)
            # IP记录偏移值+4可以丢弃前4字节的IP地址信息。
            #(c, a) = self.getAddr(o2 + 4)
            (c, a) = self.getAddrSafe(o2 + 4)
            return (c, a)
        else:
            return ('未知', '未知')
         
    def output_all_record(self, first, last):
        for i in range(first, last):
            o = self.firstIndex +  i * 7
            ip = socket.inet_ntoa(pack('!I', unpack_from('<I', self.img, o)[0]))
            offset = self.byte3offset(o + 4)
            (c, a) = self.getAddrSafe(offset + 4)
            yield (ip, offset, c, a)
 
 
def main():
    i = IPInfo('qqwry.dat')

    if len(sys.argv) < 2:
        print("Usage: %s ip_addr" % sys.argv[0])
        sys.exit()
    (c, a) = i.getIPAddr(sys.argv[1])
 
    print('%s %s/%s' % (sys.argv[1], c, a))
 
if __name__ == '__main__':
    main()

