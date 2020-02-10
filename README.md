1、重构Sublist3r，优化原API模块中的缺陷,添加常用接口以及删除无用接口，
并使用Django框架写了个web可视化页面。

2、对搜索引擎的模块进行优化,在原有的进程中增加多线程，提高爬取效率。

本程序共集成以下API接口以及第三方搜索引擎：

* 网页搜索引擎（Bing，Baidu,Google(镜像)）
* DNS历史记录查询 （bufferover,threatcrowd)
* 空间搜索引擎(Shodann,zoomeye,virustotal,threatminer）
* SSL证书(crt.sh,）
* 第三方查询接口 (ce.baidu.com,site.ip138.com）

3、集成lijiejie前辈的subDomainsBrute子域名爆破,优化协程兼容本程序。

4、对获取的子域名提取网页标题，添加masscan对获取子域名进行端口扫描。

~~5、将任务结果信息进行输出并使用SSL邮件服务器进行通知(部分vps限制smtp协议)。

v1.0版本：
![](http://raw.githubusercontent.com/c1y2m3/Subatk/master/doc/snapshot_1.png)
![](http://raw.githubusercontent.com/c1y2m3/Subatk/master/doc/snapshot.png)~~
v1.1版本：
![](http://raw.githubusercontent.com/c1y2m3/Subatk/master/doc/cmd.png)
![](http://raw.githubusercontent.com/c1y2m3/Subatk/master/doc/cmd1.png)
![](http://raw.githubusercontent.com/c1y2m3/Subatk/master/doc/cmd2.png)

### 安装使用：
### centos系统下环境配置：

```
自动化安装脚本（使用root权限运行）：
bash update.sh
启动项目：
python3 manage.py runserver 0:0:0:0:8888
访问地址：http://ip:8888/index
```


```
# 安装环境爬坑记录：
yum install python3-devel
yum install gcc-c++
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 安装chrome-browser
wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm --no-check-certificate  
sudo yum install google-chrome-stable_current_x86_64.rpm

# 安装chromedriver：一个用来和chrome交互的接口
sudo yum install chromedriver
如果系统没有这个安装包，则使用以下方法：
wget https://chromedriver.storage.googleapis.com/2.35/chromedriver_linux64.zip
unzip chromedriver_linux64.zip &  mv chromedriver /usr/bin/ & chmod +x /usr/bin/chromedriver

# 安装masscan：
项目地址：https://github.com/robertdavidgraham/masscan
yum install git gcc make libpcap-devel
cd masscan && make &&cp /root/masscan/bin/masscan /bin 
或者修改config.ini 中PATH的masscan_p 对应masscan绝对路径

```
