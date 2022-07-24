#!/bin/bash

services_start=( 'sas_servers_omr' 'sas_servers_ode' 'sas_servers_wip' 'sas_servers_rules' 'elasticsearch' 'sas_servers_tas' 'sas_servers_midtier' )
services_stop=( 'sas_servers_midtier' 'sas_servers_tas' 'elasticsearch' 'sas_servers_rules' 'sas_servers_wip' 'sas_servers_ode' 'sas_servers_omr' )
retVal=0
SCRIPT_NAME="$(basename "$0")"

if [ "$EUID" -ne 0 ]; then
        echo "Running as `id -u`. Please run as root."
        exit 1
fi

if [ "$#" -ne 1 ]; then
        echo "Running with $# arguments. Only one argument is accepted."
        echo "Please re-run with start or stop."
        exit 2
fi

if [ $1 = "start" ]; then
        for service in "${services_start[@]}"; do
                echo "Starting $service" && systemctl start "$service"
        done
elif [ $1 = "stop" ]; then
        for service in "${services_stop[@]}"; do
                echo "Stopping $service" && systemctl stop "$service"
        done
elif [ $1 = "status" ]; then
    for service in "${services_start[@]}"; do
        test=$(systemctl status $service | head -3 | tail -1 | grep "active (running)")
        temVal=$?
        if [ $temVal -ne 0 ]; then
                retVal+=$temVal
                echo "$service is DOWN"
        fi
    done
    if [ $retVal -eq 0 ]; then
        for service in "${services_start[@]}"; do
                echo "$service is UP"
        done
    fi
else
        echo "Running with $1. Please re-run with start or stop."
        exit 3
fi