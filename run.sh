#!/bin/bash
read
read -p "Password for server certificate's private key: " serverPass
read -p "Password for CA certificate's private key: " CAPass
nohup python app.py $serverPass > ./volume/server_log.txt 2>&1 &
python sign_certificates.py $serverPass $CAPass > ./volume/ca_log.txt 2>&1
# socat -T10 TCP4-LISTEN:5002,fork,reuseaddr,bind=0.0.0.0 EXEC:'python sign_certificates.py'
