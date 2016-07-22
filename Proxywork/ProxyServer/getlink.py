import urllib2
import re
import requests
import random
from socket import error as SocketError
from requests.exceptions import ConnectionError


import errno
from time import sleep

listPics = []
listAudio = []
listGzip = []
linksArray = []


requests.adapters.DEFAULT_RETRIES = 5

def getlinks(tmp1,tmp2): # para useless just for thread
    #http://soundrown.com http://thequietplaceproject.com' 'http://www.noisli.com'
    listLinks = ['http://www.cnblogs.com','http://sc.chinaz.com/yinxiao','http://www.csdn.net','http://www.cfan.com.cn']

    #connect to a URL
    for link in listLinks:
        website = urllib2.urlopen(link)
    #read html code
        html = website.read()
    #use re.findall to get all the links
        links = re.findall('"((http|ftp)s?://.*?)"', html)      # regex get link
        picTag = 0
        audioTag = 0
        for key,value in links:                                 # child link
            linksArray.append(key)                              # push into array List
	    if key.find("png") != -1 or key.find("jpg") != -1 or key.find("gif")!= -1:
               # print key
 	        if len(listPics) < 30:	
  	            listPics.append(key)
	        else: 
	            picTag = 1
   	        #print len(listPics)
            if key.find("mp3") != -1 or key.find("wav") != -1:
	       # print key
	        if len(listAudio) < 30:
	            listAudio.append(key)
    	        else:
	    	    audioTag = 1
	    if picTag == 1 and audioTag == 1:
	        break
	#data = requests.get(key)
	#head = data.headers
	
    for i in  listPics:
        print i
    for i in listAudio:
        print i

    for num in range(10):
        print num
        text_file = requests.head(url = linksArray[num])
        #print text_file.headers
        if text_file.headers.values().count('gzip') > 0:
   	    headers_file = ""
            for key,value in text_file.headers.items():
	        headers_file = headers_file + key + ":" + value + '\n'
            print headers_file
	#print linksArray[num]
  	    listGzip.append(linksArray[num])
    for i in listGzip:
        print i
    

def getpic_header():
    randomNum = random.randint(1,len(listPics))
    print randomNum
    text_file = requests.head(url = listPics[randomNum],allow_redirects=True)
    headers_file = "HTTP/1.1 200 OK\n"
    for key, value in text_file.headers.items():
	headers_file = headers_file + key + ":" + value + "\n"
    return headers_file

def getaudio_header():
    randomNum = random.randint(1,len(listAudio))
    print randomNum  # only can use get to access,I don't know why
    text_file = requests.get(url = listAudio[randomNum],allow_redirects=True)
    
    headers_file = "HTTP/1.1 200 OK\n"
    for key, value in text_file.headers.items():
	headers_file = headers_file + key + ":" + value + "\n"
    return headers_file



def getgzip_header():
    randomNum = random.randint(1,len(listGzip)-1)
    print randomNum
    text_file = requests.head(url = listGzip[randomNum],allow_redirects=True)
    headers_file = "HTTP/1.1 200 OK\n"
    for key, value in text_file.headers.items():
	headers_file = headers_file + key + ":" + value + "\n"
    return headers_file

#getlinks()
#print getpic_header()
#print getaudio_header()
#print getgzip_header()
