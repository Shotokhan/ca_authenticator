#!/bin/bash

if [[ -z "$serverPass" || -z "$CAPass" ]]
then
	read
	read -p "Password for server certificate's private key: " serverPass
	read -p "Password for CA certificate's private key: " CAPass
fi
# tcpdump host 10.5.0.4 -i any -w ./volume/capture.pcap &
python app.py $serverPass $CAPass > ./volume/server_log.txt 2>&1
