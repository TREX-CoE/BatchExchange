#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "This script must be run as root!"
  exit
fi

INSTALL_PATH="/usr/local/share/trex_server"
mkdir -p $INSTALL_PATH

# copy server to destination
echo "Copying files to ${INSTALL_PATH}"
cp -rp . ${INSTALL_PATH}
cp 	trex_server.service /etc/systemd/system/

cd ${INSTALL_PATH}
# reset venv and install dependencies
echo "Rebuilding venv"
rm -r venv
python3 -m venv venv
source venv/bin/activate && pip3 install wheel && pip3 install -r requirements.txt

# activate service which executes start_trex_server.sh
echo "Setting up service"
systemctl daemon-reload
systemctl enable --now trex_server.service
echo "Done"