
#Shadowsocks-Convert-Channel
--------
Based on a Covert Channel of shadowsocks-lighter

[TOC]

##项目介绍
-----
- **Shadowsocks-Convert-Channel**是一个基于HTTP协议的隐蔽通道，在研读Shadowsocks-lighter(源作者搜不到了，知道的希望告诉我)源码的基础上构建而成。
-  **隐蔽通道(Convert Channel)**是以信息隐藏的技术手段为基础，通过不安全信道以及公开的信道传输隐蔽信息的一种通信方法。隐蔽通道一般利用网络传输，通信双方之间相互传输的数据包在外表上看是没有异常的，通常都是通信双方约定好数据如何编码，如何转换，如何伪装，接收数据一方如何识别具有隐藏信息的数据包，以及如何进行原始信息的还原动作。
-  **基于HTTP协议的隐蔽通道**，首先需要寻找HTTP协议中的“漏洞”，可以进行更改，以及可以进行替换的字段。之后需要伪装要进行传输的数据，进行一定规则的变换，或者加密等。最后将处理过的密文嵌入选择的字段中，组合成数据报文，即HTTP请求包或响应包发送出去。等待接收方的读取与解析（见下图）。
![基于HTTP协议的隐蔽通道](./1469084826761.png)
- 该通道在原有shadowsocks加密的基础上，又对代理通道传输的数据再一次使用AES加密。
- 使用了python爬虫动态抓取网页链接
##运行环境
	操作系统：     Ubuntu 14.04 LTS 
	系统内核版本： 3.13.0-24-generic
	开发语言：     Python 2.7.6
	需要安装的Python第三方库：socket、SocketServer、Crypto、binascii、thread、requests等

##使用方法
此隐蔽通道分为客户端与服务端，因此需要两台linux设备，或一台设备+Ubuntu虚拟机
###1.  配置环境
使用如下的命令安装Python以及所依赖的库：
**Code block**
```
sudo apt-get install python
sudo apt-get install python-pip
pip install requests
``` 
**确认安装的Python版本**
安装的python的版本
```python –version ```
保证安装的是python 2.7.6版本其他版本不能保证能稳定运行

###2.  配置参数
@(运行要求:) 两台计算机设备需要连接同一个路由器的网络，就是需要处于同一个网段。不是局域网的情况未测试。

- [1]   
在客户端代理程序中ProxyClient中找到config.json
内容如下
	{
			"server":"192.168.29.29",    //服务端的IP地址
		    "server_port":8086,             //服务端的代理端口号
		    "local_port":1030,              //本地服务的端口号
		    "password":"pwd",              //共享的密码
		    "timeout":600                     //超时时长
	}

一般只修改服务端的IP地址就可以跑起来了。

------------
- [2] 
服务端ProxyServer 端,同样也有这样的配置文件

	{
	    "server":"127.0.0.1",
	    "server_port":8086,
	    "local_port":1030,
	    "password":"pwd",
	    "timeout":600
	}
服务端默认配置可以不修改，如果客户端修改了，服务端一样也要修改。

----
- [3]
在服务端由于另开了一个线程用于传输数据，因此也需要配置成服务端的IP和端口号
需要配置的地方：
 `thread.start_new_thread(sendToClientTest,('192.168.29.29',50007,))`
 
**serverAesEncry.py**
```python
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

    # two thread send Custom packet & get web link 
    thread.start_new_thread(getlink.getlinks,(1,1))
    
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
```

如果修改了服务端的端口号，那么本地这里也要同步修改：
**localAesEncry.py	**
`thread.start_new_thread(sendToServer,(SERVER,50007))`
###3. 运行命令
如果配置正确，那么就可以启动这个代理通道了。

- [1] 启动客户端
cd 到PythonClient目录中
启动：
`python serverAesEncry.py`
- [2] 启动服务端
cd到PythonServer目录中
启动:
`python localAesEncry.py`

##效果呈现
![代理模型图](./绘图3通道总揽.png)
##[1] 隐蔽通道方法一
- POST报文或者Cookie字段中添加
	客户端向服务端传送隐蔽信息，常使用的是向Cookie中添加一项的方法。一般情况下Cookie类似如下：
	
	```http
	Cookie: CNZZDATA5299104=cnzz_eid%3D2029885460-1462349590-null%26ntime%3D1462349590; AJSTAT_ok_times=1; CNZZDATA4059881=cnzz_eid%3D419224721-1462354564-null%26ntime%3D1462350058; CNZZDATA3980738=cnzz_eid%3D1707150836-1462423922-null%26ntime%3D1462423922
If-Modified-Since: Wed, 04 May 2016 09:59:21 GMT
	```
	
	- 构造方法为：如果想添加一项，就需要构造一个name字段，一个value字段。本论文中构造name字段使用了Cookie中第一个name经过变化得来，变换方式为在原来name字段的尾部加上“_id”字符串，构成新的字段，value字段保存需要的传送的隐蔽数据。
	
	**效果图**
	>客户端向服务端发送的密文:
![Alt text](./Untitled.png)
		>已经添加隐蔽数据的数据报文截图为:
![Alt text](./Untitled1.png)
		>服务端接收到隐蔽数据，并经过解密，还原出原始数据
![Alt text](./Untitled2.png)

##[2]隐蔽通道方法二
- 由于服务端发送的是客户机请求的响应报文，因此，服务端给客户端传送隐蔽信息可以自己构造响应报文，然后把构造的响应报文嵌入隐蔽数据，发给客户端。当发送数据报文时，可以使用HTTP网页上最经常使用的图片，音频，或者以压缩格式传输的数据包。如果每次都只发送固定的响应报文给客户端，那么很容易被检测与发现。因此本论文使用了动态抓取网站链接的方式，并随机变换图片，音频，压缩包构建待发送的数据报文，这样使网页流量看起来更像真实的数据报文。
	>发送给客户端的隐蔽信息
![Alt text](./1469215535432.png)
	>加入隐蔽信息的图片数据报文
![Alt text](./1469215574856.png)
	>客户端接收到服务端发来的数据报文：
![Alt text](./1469215610419.png)
	>客户端接收到隐蔽数据信息并还原解密：
![Alt text](./1469215645891.png)

##总结
- 本文也只是在原有shadowsocks-lighter的源码基础上，加了一层对网页数据包修改的动作，也许可以达到对传输数据的保护作用，仅用于科学实验。制作过程中熟悉了Python语言。特别感谢尹老师给我的指导，您把循循善诱教书育人这两个词体现的淋漓尽致，非常感谢尹老师在大学给予的引导与教育。

- 自觉本人资质愚笨，属于没有什么想法的程序员，算法研习了许久都没有进展。是一个彻彻底底的码农。如果您觉得这篇文章对您有帮助，那就再好不过了。另转载请注明出处。第一次认认真真的写东西，利用零碎时间写了一周，只想为开源贡献一点微薄之力！
