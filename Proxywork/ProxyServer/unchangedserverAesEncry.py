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
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

import random
import time
import thread
code = ""

listpacketgzip = [
'''HTTP/1.1 200 OK
Date: Tue, 19 Apr 2016 09:15:35 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Vary: Accept-Encoding
Cache-Control: public, max-age=26
Expires: Tue, 19 Apr 2016 09:16:02 GMT
Last-Modified: Tue, 19 Apr 2016 09:15:32 GMT
X-UA-Compatible: IE=10
Content-Encoding: gzip''',
'''HTTP/1.1 200 OK
Server: openresty
Date: Tue, 19 Apr 2016 09:16:16 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Keep-Alive: timeout=20
Vary: Accept-Encoding
Cache-Control: private, max-age=0, must-revalidate
ETag: W/"5eec920e774e65c6563e19afbb996eb0"
X-Powered-By: PHP 5.4.28
Content-Encoding: gzip''',
'''HTTP/1.1 200 OK
Server: openresty
Date: Tue, 19 Apr 2016 09:22:12 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Keep-Alive: timeout=20
Vary: Accept-Encoding
Last-Modified: Tue, 19 Apr 2016 09:10:02 GMT
Vary: Accept-Encoding
ETag: W/"5715f5ea-1932b"
Content-Encoding: gzip'''
]

listpacketpic = [
'''HTTP/1.1 200 OK
Date: Tue, 19 Apr 2016 08:21:55 GMT
Server: nginx/1.4.4
Content-Length: 2798
Accept-Ranges: bytes
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: X-Log, X-Reqid
Access-Control-Max-Age: 2592000
Content-Disposition: inline; filename="1460535308634_634.jpg"
Content-Transfer-Encoding: binary
Last-Modified: Wed, 13 Apr 2016 08:15:09 GMT
Content-Type: image/jpeg
ETag: "Fvbp9L1xqUrRlLlvwy2Gkm0cSGwJ"
X-Log: mc.g;IO:1/304
X-Reqid: CnsAAIJYexi2tEYU
X-Qiniu-Zone: 0
Cache-Control: public, max-age=31536000
Age: 1
X-Via: 1.1 hdwt45:80 (Cdn Cache Server V2.0), 1.1 yuwang203:8 (Cdn Cache Server V2.0)
Connection: keep-alive''',
'''HTTP/1.1 200 OK
Server: Tengine
Content-Type: image/png
Content-Length: 2836
Connection: keep-alive
Date: Sun, 13 Dec 2015 06:14:17 GMT
x-oss-request-id: 566D0CB9A9929D396C15FBE1
Accept-Ranges: bytes
ETag: "7406CD839C1F74AC67186E2B2E852A1C"
Last-Modified: Mon, 16 Nov 2015 11:06:28 GMT
x-oss-object-type: Normal
Via: cache43.l2et15-1[0,200-0,H], cache10.l2et15-1[1,0], kunlun4.cn74[0,200-0,H], kunlun5.cn74[0,0]
Age: 11070478
X-Cache: HIT TCP_MEM_HIT dirn:11:732038061
X-Swift-SaveTime: Mon, 15 Feb 2016 04:49:57 GMT
X-Swift-CacheTime: 7776000
access-control-allow-origin: *
Timing-Allow-Origin: *
EagleId: deba319e14610577354518910e''',
'''HTTP/1.1 200 OK
Server: Tengine
Content-Type: image/png
Content-Length: 2723
Connection: keep-alive
Date: Thu, 10 Dec 2015 19:12:43 GMT
x-oss-request-id: 5669CEAB41CEED0315664513
Accept-Ranges: bytes
ETag: "596D39541FCC57C2E7AB4553D6E952AB"
Last-Modified: Mon, 16 Nov 2015 11:06:29 GMT
x-oss-object-type: Normal
Via: cache34.l2et15-1[0,200-0,H], cache32.l2et15-1[0,0], kunlun5.cn74[0,200-0,H], kunlun6.cn74[0,0]
Age: 11282972
X-Cache: HIT TCP_MEM_HIT dirn:10:879905190
X-Swift-SaveTime: Mon, 15 Feb 2016 04:49:57 GMT
X-Swift-CacheTime: 7776000
access-control-allow-origin: *
Timing-Allow-Origin: *
EagleId: deba319f14610577354875284e'''
]

listpacketaudio = [
'''HTTP/1.0 206 Partial Content
Date: Thu, 18 Feb 2016 08:38:58 GMT
Server: ngx_openresty/1.4.3.6
Content-Type: audio/mpeg;charset=UTF-8
x-nos-request-id: a675f2ea0aa000000152853ccdca849d
ETag: 4a0c99e016aa019b04b442907e60bd94
Content-Disposition: inline; filename="45e8%2F01d8%2Fd032%2F4a0c99e016aa019b04b442907e60bd94.mp3"
Last-Modified: Tue, 02 Jun 2015 14:32:51 Asia/Shanghai
Content-Range: bytes 0-3304622/3304623
Content-Length: 3304623
Age: 5273574
Via: 1.0 sdbz31:8180 (Cdn Cache Server V2.0), 1.0 yuwang217:6080 (Cdn Cache Server V2.0)
Connection: keep-alive''',
'''HTTP/1.0 206 Partial Content
Date: Tue, 19 Apr 2016 00:38:07 GMT
Server: ngx_openresty/1.4.3.6
Content-Type: audio/mpeg;charset=UTF-8
x-nos-request-id: 6b440c7b0aa000000153eeba89ed849d
ETag: 6c14aff874ae4db2efb457d4b668ece4
Content-Disposition: inline; filename="02b6%2Fef5a%2F51da%2F6c14aff874ae4db2efb457d4b668ece4.mp3"
Last-Modified: Tue, 02 Jun 2015 23:00:15 Asia/Shanghai
Content-Range: bytes 0-3124704/3124705
Content-Length: 3124705
Age: 32111
Via: 1.0 zhouwangtong49:8104 (Cdn Cache Server V2.0), 1.0 yuwang217:553 (Cdn Cache Server V2.0)
Connection: keep-alive''',
'''HTTP/1.0 206 Partial Content
Date: Tue, 19 Apr 2016 09:34:07 GMT
Server: ngx_openresty/1.4.3.6
Content-Type: audio/mpeg;charset=UTF-8
x-nos-request-id: 326e22120aa000000152925c85ee849b
ETag: e8075ce6a5944c9ace624a4f9f82fdb5
Content-Disposition: inline; filename="2b1c%2F5560%2F911a%2Fe8075ce6a5944c9ace624a4f9f82fdb5.mp3"
Last-Modified: Fri, 16 Oct 2015 11:19:53 Asia/Shanghai
Content-Range: bytes 0-3808904/3808905
Content-Length: 3808905
Via: 1.0 wangtong27:8108 (Cdn Cache Server V2.0), 1.0 jyw216:12680 (Cdn Cache Server V2.0)
Connection: keep-alive'''
]

class AESClipher:
    def __init__(self,key):
        self.key = key
	self.mode = AES.MODE_CBC

    def encrypt(self,text):
	cryptor = AES.new(self.key, self.mode, self.key)
	length = 16
	count = len(text)
	add = length - (count % length)
	text = text + ( '\0' * add)
	self.ciphertext = cryptor.encrypt(text)
	return b2a_hex(self.ciphertext)

    def decrypt(self,text):
        cryptor = AES.new(self.key, self.mode, self.key)
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
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

def decryptInformation(code):
    encryObject = AESClipher('keyskeyskeyskeys')
    if len(code) > 0:
        afterDecrypt = encryObject.decrypt(code)
        print "after decrypt..." , afterDecrypt
	#time.sleep(10)

def handlePacketDataFetch(data):
    global isDataTran
    index = data.find("Cookie")
    #print ">>>>data>>>"+data
    if data.find("POST") != -1:
        #dosomethind()
        codeStart = data.find("description")
        code = data[codeStart+12:]
	print len(code),"length-------------<>"
	if len(code) != 0:                    # data already fetch
	    isDataTran = 1

        print code,"the secure code is :" # take down the information
        decryptInformation(code)          # decrypt received data

        addValue = data[codeStart-1:]
        print addValue,"the addValue is :------"
        data = data.replace(addValue,"",1)# remove the addValue
        print "After remove -----"
        #print data
    elif index  != -1:
        spot = data.find(";",index,-1)
        codeStart = data.find("=",spot,-1)
        codeEnd = data.find(";",spot+1,-1)
	print codeStart,codeEnd,"-----<><><><><>"
        code = data[codeStart+1:codeEnd]

        print code ,"code-------"
        decryptInformation(code)          # decrypt received data

        addValue = data[spot+2:codeEnd+1]
        print addValue,"addValue--------"
        #data = data.strip(addValue)
        data = data.replace(addValue,"",1)
        #print data,"changed-data------"
    return data

""" don't need send ack packet ,TCP do it already
def sendAckPacket(data):
    dateStart = data.find("Date")
    if dateStart != -1:
        firstSpot = data.find(":",dateStart,-1)
        secondSpot = data.find(":",firstSpot+1,-1)
        print data[secondSpot-1],data[secondSpot+2],data[secondSpot+5],"------------------------"
        tmpList = list(data)
        if int(data[secondSpot-1]) % 2 == 0:
            tmpList[secondSpot-1] = str(int(tmpList[secondSpot-1])+1)
        if int(data[secondSpot+2]) % 2 == 0:
            tmpList[secondSpot+2] = str(int(tmpList[secondSpot+2])+1)
        if int(data[secondSpot+5]) % 2 == 0:
            tmpList[secondSpot+5] = str(int(tmpList[secondSpot+5])+1)
        data = ''.join(tmpList)
        print data[secondSpot-1],data[secondSpot+2],data[secondSpot+5],"++++++++++++++++++++"
    return data
"""





class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
	    #global isDataTran
	    #haveData = 0
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(4096)
		    
		    #decrypt early
		    data =  self.decrypt(data)
		    print "------------------"
		    print data
		    #have data then fetch 
		    postMethod = data.find("description")
		    cookieMethod = -1
		    index = data.find("Cookie")
		    if index != -1:
		        nameEnd = data.find("=",index,-1)
		        name = data[index+8:nameEnd]
			name = name + "_id"
		        cookieMethod = data.find(name)
		    if postMethod != -1 or cookieMethod != -1:
			#time.sleep(10)	
		        data = handlePacketDataFetch(data)  #handle the data,Fetch the secret information
 
                    if len(data) <= 0:
                        break
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = remote.recv(4096)
		    
                    #data = sendToClient(data) # hide data insert

		    if len(data) <= 0:
                        break
                    result = send_all(sock, self.encrypt(data))
                    if result < len(data):
                        raise Exception('failed to send all data')

        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)

    def handle(self):
        try:
            sock = self.connection
            
	    #don't need link from itself ,from a proxy 
	    addrtype = ord(self.decrypt(sock.recv(1)))      # receive addr type
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))   # get dst addr
            elif addrtype == 3:
                addr = self.decrypt(
                    self.rfile.read(ord(self.decrypt(sock.recv(1)))))       # read 1 byte of len, then get 'len' bytes name
            else:
                # not support
                logging.warn('addr_type not support')
                return
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))    # get dst port into small endian
	    
	    

	    #addr = "120.52.73.90"
            try:
                logging.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.connect((addr, port[0]))         # connect to dst
            except socket.error, e:
                # Connection refused
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)


def sendToClientDataHandle(data):
    stringToClient = "this data is a test ,send to client"
    encryptObject = AESClipher('keyskeyskeyskeys')
    #afterEncrypt = "dtStart"
    afterEncrypt = encryptObject.encrypt(stringToClient)   # sign where data start & end
    #print "stringToClient encry" + encryptObject.encrypt(stringToClient)
    print "afterEncrypt>>>" + afterEncrypt

    global order_index

    if order_index > 3 : # three method hide data
	order_index = 1


    data = data + '\n\n' + afterEncrypt
    print "after insert data" + data
    order_index = order_index + 1

    return data

order_index = 1
def sendToClientTest(HOST,PORT):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((HOST,PORT))
    s.listen(1)
    while 1:
        conn,addr = s.accept()
        print 'Connected by ',addr
        while 1: 
 	    data = conn.recv(1024)
	    #print data

	    randomNum = random.randint(0,3)
	    print randomNum,"........."
     	    if order_index == 1:
	        data = listpacketpic[randomNum-1]
	    elif order_index == 2:
		data = listpacketgzip[randomNum-1]
	    elif order_index == 3:
		data = listpacketaudio[randomNum-1]
	    data = sendToClientDataHandle(data)
	    print "after insert data,,,,"+data
	    # do something
	    conn.sendall(data)
    conn.close()
    thread.exit()

if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')

    print 'shadowsocks v0.9'

    with open('config.json', 'rb') as f:
        config = json.load(f)

    SERVER = config['server']
    PORT = config['server_port']
    KEY = config['password']

    optlist, args = getopt.getopt(sys.argv[1:], 'p:k:')
    for key, value in optlist:
        if key == '-p':
            PORT = int(value)
        elif key == '-k':
            KEY = value

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    
    thread.start_new_thread(sendToClientTest,('192.168.29.29',50007,))

    encrypt_table = ''.join(get_table(KEY))
    decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    if '-6' in sys.argv[1:]:
        ThreadingTCPServer.address_family = socket.AF_INET6
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error, e:
        logging.error(e)
    
