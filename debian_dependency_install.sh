#!/bin/sh

echo "Loading Python3"
sudo apt-get update
sudo apt-get install python3

echo "Installing pip3"
sudo apt-get install -y python3-pip

echo "installing python dependencies"
pip3 install tqdm
