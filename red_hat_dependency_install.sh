#!/bin/sh

echo "Downloading Yum"
wget http://yum.baseurl.org/download/3.4/yum-3.4.3.tar.gz
echo "Extracting Yum"
gunzip yum-3.4.3.tar.gz
tar -xvf yum-3.4.3.tar
echo "Installing Yum"
cd yum-3.4.3/
make
echo "Installing Python3"
sudo yum install python3
echo "Installing pip3" 
sudo yum install pip3
echo "Loading Python dependencies"
pip3 install tqdm
pip3 install requests
pip3 install htsget
