In development.....

1、重构Sublist3r，优化原API模块中的缺陷,添加常用接口以及删除无用接口。

2、对搜索引擎的模块进行优化,在原有的进程中增加多线程，提高爬取效率。

本程序共集成以下API接口以及第三方搜索引擎：

* 网页搜索引擎（Bing，Baidu,Google(镜像)）
* DNS历史记录查询 （bufferover,threatcrowd)
* 空间搜索引擎(Shodann,zoomeye,virustotal,threatminer）
* SSL证书(crt.sh,）
* 第三方查询接口 (ce.baidu.com,site.ip138.com）

3、集成lijiejie前辈的subDomainsBrute子域名爆破,优化协程兼容本程序。

4、对获取的子域名提取网页标题，添加masscan对获取子域名进行端口扫描。

5、将任务结果信息进行输出并使用SSL邮件服务器进行通知(部分vps限制smtp协议)。
![](http://raw.githubusercontent.com/c1y2m3/Subatk/master/doc/snapshot_1.png)
![](http://raw.githubusercontent.com/c1y2m3/Subatk/master/doc/snapshot.png)

### 安装使用：
### centos系统下环境配置：
```
# 安装selenium
pip install selenium

# 安装chrome-browser
wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm --no-check-certificate  
sudo yum install google-chrome-stable_current_x86_64.rpm

# 安装chromedriver：一个用来和chrome交互的接口
sudo yum install chromedriver

# 安装masscan：
yum install masscan
```
