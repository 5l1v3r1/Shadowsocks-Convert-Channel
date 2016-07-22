#!/usr/bin/env python

# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys

try:
    import gevent, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'

import socket
import select
import SocketServer
import struct
import string
import hashlib
import os
import json
import logging
import getopt
from Crypto.Cipher import AES        # make sure you client already install the pycrypto pack
from binascii import b2a_hex, a2b_hex
import time
import requests
import thread
import random

theOriginData = 0                    # the data you want to transmit after encrypt
haveData = 0                         # whether there have data to transmit

list_packetpic = [
        '''GET /upload/base/1460535308634_634.jpg HTTP/1.1

        Host: img.knowledge.csdn.net

        Connection: keep-alive

        Pragma: no-cache

        Cache-Control: no-cache

        Accept: image/webp,*/*;q=0.8

        User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36

        Referer: http://www.csdn.net/?ref=toolbar

        Accept-Encoding: gzip, deflate, sdch

        Accept-Language: zh-CN,zh;q=0.8,en-GB;q=0.6,en;q=0.4,af;q=0.2

        Cookie: uuid_tt_dd=-8017200687387492298_20160413; __message_district_code=360000; Hm_lvt_6bcd52f51e9b3dce32bec4a3997715ac=1461057551; Hm_lpvt_6bcd52f51e9b3dce32bec4a3997715ac=1461057682; dc_tos=o5vjby; dc_session_id=1461057384270; __message_sys_msg_id=0; __message_gu_msg_id=0; __message_cnel_msg_id=0; __message_in_school=0''',
        '''GET /www/images/pic_foot_gongshang.png HTTP/1.1

        Host: c.csdnimg.cn

        Connection: keep-alive

        Pragma: no-cache

        Cache-Control: no-cache

        Accept: image/webp,*/*;q=0.8

        User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36

        Referer: http://www.csdn.net/?ref=toolbar

        Accept-Encoding: gzip, deflate, sdch

        Accept-Language: zh-CN,zh;q=0.8,en-GB;q=0.6,en;q=0.4,af;q=0.2''',
        '''GET /www/images/pic_foot_report110.png HTTP/1.1

        Host: c.csdnimg.cn

        Connection: keep-alive

        Pragma: no-cache

        Cache-Control: no-cache

        Accept: image/webp,*/*;q=0.8

User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36

Referer: http://www.csdn.net/?ref=toolbar

Accept-Encoding: gzip, deflate, sdch

Accept-Language: zh-CN,zh;q=0.8,en-GB;q=0.6,en;q=0.4,af;q=0.2'''
        ]

list_packetgzip = [
        '''GET / HTTP/1.1

        Host: www.cnblogs.com

        Connection: keep-alive

        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

        User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36

        HTTPS: 1

        Accept-Encoding: gzip, deflate, sdch

        Accept-Language: zh-CN,zh;q=0.8,en-GB;q=0.6,en;q=0.4,af;q=0.2

        Cookie: .CNBlogsCookie=5700372B7B15C284BEFEC1BE0C0D7E9B82A7865740887F6513D2271F0EB1B756E4EABA5527C5F5C97167DA06FDBE1511D5CE84CA4BB9E034977B83B47EE7ED6C4189B31EB1586908D867C4991465F078F02A0AE4; _ga=GA1.2.187821670.1460549367

        If-Modified-Since: Tue, 19 Apr 2016 08:47:07 GMT''',
        '''GET /vipzjyno1/article/details/21039349 HTTP/1.1

        Host: blog.csdn.net

        Connection: keep-alive

        Pragma: no-cache

        Cache-Control: no-cache

        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

        User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36

        HTTPS: 1

        Accept-Encoding: gzip, deflate, sdch

        Accept-Language: zh-CN,zh;q=0.8,en-GB;q=0.6,en;q=0.4,af;q=0.2

        Cookie: bdshare_firstime=1460548835351; uuid_tt_dd=-8017200687387492298_20160413; uuid=6b208c41-9e08-41ba-866d-8a0930de61ee; __message_district_code=360000; avh=21039349; dc_tos=o5vijj; dc_session_id=1461056671244; __message_sys_msg_id=0; __message_gu_msg_id=0; __message_cnel_msg_id=0; __message_in_school=0''',
        '''GET /?ref=toolbar HTTP/1.1

        Host: www.csdn.net

        Connection: keep-alive

        Pragma: no-cache

        Cache-Control: no-cache

        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36

HTTPS: 1

Referer: http://blog.csdn.net/vipzjyno1/article/details/21039349

Accept-Encoding: gzip, deflate, sdch

Accept-Language: zh-CN,zh;q=0.8,en-GB;q=0.6,en;q=0.4,af;q=0.2

Cookie: uuid_tt_dd=-8017200687387492298_20160413; __message_district_code=360000; Hm_lvt_6bcd52f51e9b3dce32bec4a3997715ac=1461057551; Hm_lpvt_6bcd52f51e9b3dce32bec4a3997715ac=1461057682; dc_tos=o5vjby; dc_session_id=1461057384270; __message_sys_msg_id=0; __message_gu_msg_id=0; __message_cnel_msg_id=0; __message_in_school=0''']

list_packetaudio = [
        '''GET /m10.music.126.net/20160419175652/b5f7114404d414f3bca43e4e4baf4542/ymusic/45e8/01d8/d032/4a0c99e016aa019b04b442907e60bd94.mp3?wshc_tag=1&wsts_tag=5715fb08&wsid_tag=dbe5e6c9&wsiphost=ipdbm HTTP/1.1

        Host: 218.197.116.217

        Connection: keep-alive

        Accept-Encoding: identity;q=1, *;q=0

        User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36

        Accept: */*

        Referer: http://music.163.com/

        Accept-Language: zh-CN,zh;q=0.8,en-GB;q=0.6,en;q=0.4,af;q=0.2

        Range: bytes=0-''',
        '''GET /m10.music.126.net/20160419175818/2d8f1941ca959a3a84ae1055336f90de/ymusic/02b6/ef5a/51da/6c14aff874ae4db2efb457d4b668ece4.mp3?wshc_tag=0&wsts_tag=5715fb5e&wsid_tag=dbe5e6c9&wsiphost=ipdbm HTTP/1.1

        Host: 218.197.116.217

        Connection: keep-alive

        Accept-Encoding: identity;q=1, *;q=0

        User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36

        Accept: */*

        Referer: http://music.163.com/

        Accept-Language: zh-CN,zh;q=0.8,en-GB;q=0.6,en;q=0.4,af;q=0.2

        Range: bytes=0-''',
        '''GET /m10.music.126.net/20160419175906/77e8e492456fcf00cccc3b9c6e0856a0/ymusic/2b1c/5560/911a/e8075ce6a5944c9ace624a4f9f82fdb5.mp3?wshc_tag=0&wsts_tag=5715fb8e&wsid_tag=dbe5e6c9&wsiphost=ipdbm HTTP/1.1

        Host: 218.197.116.216

        Connection: keep-alive

        Accept-Encoding: identity;q=1, *;q=0

        User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36

        Accept: */*

        Referer: http://music.163.com/

        Accept-Language: zh-CN,zh;q=0.8,en-GB;q=0.6,en;q=0.4,af;q=0.2

        Range: bytes=0-''']

class AESClipher:
    def __init__(self,key):
        self.key = key
        self.mode = AES.MODE_CBC

    def encrypt(self,text):
        cryptor = AES.new(self.key, self.mode, self.key)
        length = 16                  # 16bit(AES-128) key , must be 16*X
        count = len(text)
        add = length - (count % length)
        text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        # turn to 0x Mode prevent coding problem
        return b2a_hex(self.ciphertext)

    # use strip to remove unnecessary space
    def decrypt(self,text):
        cryptor = AES.new(self.key, self.mode, self.key)
        check_space = 0
        for letter in text:
            if letter == ' ':
                check_space = 1
                break
        if check_space == 0:
            plain_text = cryptor.decrypt(a2b_hex(text))
            return plain_text.rstrip('\0')


def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table

def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:]) #return the byte length of send
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent

def decryptInformation(code):
    encryObject = AESClipher('keyskeyskeyskeys')
    if len(code) > 0:
        code = b2a_hex(code) # Restore data
        print 'Before hex : \n'+code + '\n'

        afterDecrypt = encryObject.decrypt(code)
        print "After decrypt : \n" + afterDecrypt
        #time.sleep(10)

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):   # Multiple inheritance
    allow_reuse_address = True

def handlePacketDataInsert(data):
    index = data.find("Cookie")
    if data.find("POST")!= -1:        #POST requery
        
        transmitData = "&description="+theOriginData
        print "transfer data : \n" + transmitData

        data = data + transmitData
    elif index != -1:
        nameEnd = data.find("=",index,-1)
        name = data[index+8:nameEnd]
        
        transmitData = name + "_id=" + theOriginData + "; "#do some changes add one value
        print "Embedded data : \n" + transmitData

        spot = data.find(";",index,-1)
        data = data[:spot+2] + str(transmitData) + data[spot+2:]

    return data

class Socks5Server(SocketServer.StreamRequestHandler):
    ''' RequesHandlerClass Definition '''
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            global getData
            global order_index
            while True:
                r, w, e = select.select(fdset, [], [])      # use select I/O multiplexing model
                if sock in r:                               # if local socket is ready for reading
                    data = sock.recv(4096) 
                    
                    data = handlePacketDataInsert(data)

                    if len(data) <= 0:                      # received all data
                        break
                    result = send_all(remote, self.encrypt(data))   # send data after encrypting
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:                             # remote socket(proxy) ready for reading
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break

                    result = send_all(sock, self.decrypt(data))     # send to local socket(application)
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)

    def send_encrypt(self, sock, data):
        sock.send(self.encrypt(data))
    
    def handle(self):
        try:
            sock = self.connection        # local socket [127.1:port]
            sock.recv(262)                # Sock5 Verification packet
            sock.send("\x05\x00")         # Sock5 Response: '0x05' Version 5; '0x00' NO AUTHENTICATION REQUIRED
            # After Authentication negotiation
            data = self.rfile.read(4)     # Forward request format: VER CMD RSV ATYP (4 bytes)
            mode = ord(data[1])           # CMD == 0x01 (connect)
            if mode != 1:
                logging.warn('mode != 1')
                return
            addrtype = ord(data[3])       # indicate destination address type
            addr_to_send = data[3]
            if addrtype == 1:             # IPv4
                addr_ip = self.rfile.read(4)            # 4 bytes IPv4 address (big endian)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:           # FQDN (Fully Qualified Domain Name)
                addr_len = self.rfile.read(1)           # Domain name's Length
                addr = self.rfile.read(ord(addr_len))   # Followed by domain name(e.g. www.google.com)
                addr_to_send += addr_len + addr
            else:
                logging.warn('addr_type not support')
                # not support
                return
            addr_port = self.rfile.read(2)
            addr_to_send += addr_port                   # addr_to_send = ATYP + [Length] + dst addr/domain name + port
            port = struct.unpack('>H', addr_port)       # prase the big endian port number. Note: The result is a tuple even if it contains exactly one item.
            try:
                reply = "\x05\x00\x00\x01"              # VER REP RSV ATYP
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)  # listening on 2222 on all addresses of the machine, including the loopback(127.0.0.1)
                self.wfile.write(reply)                 # response packet
                # reply immediately
                if '-6' in sys.argv[1:]:                # IPv6 support
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)       # turn off Nagling
                remote.connect((SERVER, REMOTE_PORT))
                self.send_encrypt(remote, addr_to_send)      # encrypted
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)

    
def handlePacketDataFetch(data): # get the string
    stat = 0 # file stream start spot
    for line in data.split('\n'):
        if not line.split():
            break 
        else:
            # the starting point to calculate the ciphertext
            stat = stat + len(line) + 1
    
    print "Tramsmit data : \n" + data
    code = data[stat+2:]
    print "Transmit data : \n" + code
    decryptInformation(code)

order_index = 1

def sendToServer(HOST,PORT):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    global order_index
    while 1: 
        randomNum = random.randint(0,3)
        if order_index == 1:
            s.sendall(list_packetpic[randomNum-1])
        elif order_index == 2:
            s.sendall(list_packetgzip[randomNum-1])
        elif order_index == 3:
            s.sendall(list_packetaudio[randomNum-1])
        
        order_index = order_index + 1

        data = s.recv(1024)
        
        handlePacketDataFetch(data)
        
    s.close()


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print 'shadowsocks v0.9'

    # test the AES code
    # pc = AESClipher('keyskeyskeyskeys') #init the code
    # e = pc.encrypt("hello,I'm here")
    # d = pc.decrypt(e)
    # print e,d

    answer = raw_input("Whether you want to transmit data, Please input (Y/N):")
    if answer == "Y" or answer == "y":
        haveData = 1
        unEncryptOriginData = str(raw_input("Input the data : "))
        encryObject = AESClipher('keyskeyskeyskeys')
        theOriginData = encryObject.encrypt(unEncryptOriginData)
        print "After encrypt : \n" + theOriginData 


    with open('config.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']

    optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:l:')
    for key, value in optlist:
        if key == '-p':
            REMOTE_PORT = int(value)
        elif key == '-k':
            KEY = value
        elif key == '-l':
            PORT = int(value)
        elif key == '-s':
            SERVER = value

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    thread.start_new_thread(sendToServer,(SERVER,50007))

    encrypt_table = ''.join(get_table(KEY))
    decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)   # s.bind(('', 80)) specifies that the socket is reachable by any address the machine happens to have.
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error, e:
        logging.error(e)

