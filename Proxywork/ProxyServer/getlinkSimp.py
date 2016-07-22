import urllib2
import re
import requests
url = 'http://www.world68.com'
#req = urllib2.Request(url)
con = requests.get(url)
doc = con.text
con.close()
links = re.findall(r'href\=\"(http\:\/\/[a-zA-Z0-9\.\/]+)\"',doc)
for a in links: 
    print a   
   # webfile = requests.get(a)    
   # textFile = webfile.headers    
    #for key, value in textFile.items():        #if value.find("image/png") != -1:        print key, ":", value
