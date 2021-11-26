#!/bin/bash
read
read -p "Password for server certificate's private key: " serverPass
read -p "Password for CA certificate's private key: " CAPass
python app.py $serverPass $CAPass > ./volume/server_log.txt 2>&1
