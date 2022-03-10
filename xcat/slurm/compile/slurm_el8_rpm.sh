#!/bin/bash

function print_help {
    echo "Usage: slurm_el8_rpm.sh <OPTIONS> SLURMVERSION SLURMRELEASE"
    echo "Example: ./slurm_el8_rpm.sh 21.08.6 \"\""
    echo ""
    echo "OPTIONS:"
    echo -e "-h|--help\tprints this"
    echo ""
    echo -e "-d|--dir\tpath for rpm packages"
    echo -e "-e|--executor\t[docker|podman] executer (default: podman)"
    echo -e "--rm\tremove image after execution"
}

if [[ $1 == "-h" || $1 == "--help" ]]; then
    print_help

    exit 0
fi

if [ $# -le 1 ]; then
    echo "Too few arguments!"
    print_help

    exit 0
fi

EXECUTOR="podman"
RPM_DIR="/tmp"
RM_IMAGE=0
while [[ $# -gt 2 ]]; do
    key="$1"

    case $key in
        -h|--help)
        print_help

        exit 0
        ;;
        -e|--executor)
        EXECUTOR="$2"
        shift # past argument
        shift # past value
        ;;
        -d|--dir)
        RPM_DIR="$2"
        shift # past argument
        shift # past value
        ;;
        --rm)
        RM_IMAGE=1
        shift # past argument
        ;;
    esac
done

SLURMVERSION=$1
SLURMRELEASE=$2

$EXECUTOR build --build-arg SLURMVERSION=$SLURMVERSION --build-arg SLURMRELEASE=$SLURMRELEASE -f ./build_slurm_el8.dockerfile -t alma_slurm .
$EXECUTOR run -v $RPM_DIR:/tmp/slurm --name build_slurm alma_slurm
$EXECUTOR rm build_slurm
if [ $RM_IMAGE -eq 1 ]; then
    $EXECUTOR rmi alma_slurm
fi
