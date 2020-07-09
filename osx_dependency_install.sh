#!/bin/sh

echo "Loading HomeBrew"
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

echo "Loading Python3"
brew install python3

echo "Loading Python DEpendencies"
pip install tqdm
pip install requests
pip install htsget
pip install psutil
