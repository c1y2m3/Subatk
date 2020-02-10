#!/bin/bash



if [ "$(whoami)" != "root" ]
then
    echo "请使用root权限运行此脚本";
    exit
fi
if [ -f "/usr/bin/python3" ];then
echo "[*] 当前系统已安装python3 "
echo "[*] 正在安装项目所需的依赖包 "
yum install gcc-c++
yum install python3-devel
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm --no-check-certificate
sudo yum install google-chrome-stable_current_x86_64.rpm
wget https://chromedriver.storage.googleapis.com/2.35/chromedriver_linux64.zip
unzip chromedriver_linux64.zip & mv chromedriver /usr/bin/&chmod +x /usr/bin/chromedriver
else
echo "[*] 正在安装python3 "
yum install python3
bash update.sh
fi
if [ -f "/usr/bin/git" ];then
echo "[*] 当前系统已安装git "
else
yum install git
fi
echo "[*] 正在安装项目所需的masscan "
git clone https://github.com/robertdavidgraham/masscan
echo "[*] 正在安装masscan所需的依赖包"
yum install git gcc make libpcap-devel
cd masscan && make &&cp /root/masscan/bin/masscan /bin && chmod +x /usr/bin/masscan
echo "[*] 依赖包安装成功,请启动项目!PS：python3 manage.py runserver 0:0:0:0:8888 "