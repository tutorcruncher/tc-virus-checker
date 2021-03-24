#!/usr/bin/env bash

set -ex

curl -sL https://deb.nodesource.com/setup_14.x | bash -
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list

export DEBIAN_FRONTEND=noninteractive

apt-get -y install software-properties-common
add-apt-repository ppa:deadsnakes/ppa
apt-get -qq update
apt-get -y install python3.8 python3.8-dev python3.8-venv
apt-get -y install python3-distutils
apt-get -y install clamav clamav-daemon
apt-get -y autoremove

rm /usr/bin/python3
ln -s /usr/bin/python3.8 /usr/bin/python3
rm /usr/bin/python
ln -s /usr/bin/python3.8 /usr/bin/python

curl -s https://bootstrap.pypa.io/get-pip.py | python

python -V
pip -V
pip install -U pip
pip -V
