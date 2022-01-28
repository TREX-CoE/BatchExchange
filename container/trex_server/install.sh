#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "This script must be run as root!"
  exit
fi

function print_help {
    echo "Usage: install.sh <OPTIONS>"
    echo ""
    echo "OPTIONS:"
    echo -e "-h|--help\tprints this"
    echo ""
    echo -e "-e|--executor\t[docker|podman] executer (default: podman)"
    echo -e "-p|--port\t Port (default: 7100)"
}

SERVICE_NAME="trex_server"
EXECUTOR="podman"
PORT="7100"
while [[ $# -gt 1 ]]; do
    key="$1"
    echo $key
    case $key in
        -h|--help)
        print_help
        exit 0
        ;;
        -e|--executor)
        EXECUTOR="$2"
        shift
        shift
        ;;
        -p|--port)
        PORT="$2"
        shift
        shift
        ;;
    esac
done

INSTALL_PATH="/usr/local/share/${SERVICE_NAME}/container"
mkdir -p $INSTALL_PATH

${EXECUTOR} build --build-arg PORT=${PORT} --no-cache -t ${SERVICE_NAME} -f ./Dockerfile ../../

cp 	${SERVICE_NAME}.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ${SERVICE_NAME}