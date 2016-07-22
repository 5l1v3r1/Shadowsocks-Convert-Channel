import urllib2
import re
import requests


listLinks = ['http://thequietplaceproject.com','http://www.noisli.com','http://www.cnblogs.com','http://soundrown.com','http://sc.chinaz.com/yinxiao']

listPics = []
listAudio = []
listGzip = []

#connect to a URL
for link in listLinks:
    website = urllib2.urlopen('http://www.world68.com/')
#read html code
    html = website.read()
#use re.findall to get all the links
    links = re.findall('"((http|ftp)s?://.*?)"', html)
    for index in links:
	print index
