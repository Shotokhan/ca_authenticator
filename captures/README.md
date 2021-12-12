# Captures
This folder contains capture files related to the protocol. <br>
At the moment, there is only one file: ```ui_flow.pcap```, which contains a full user interaction with the system:

- Access to landing page;
- Third-party authentication with Keycloak;
- Registration with CSR (the "backend" communication between the application and Keycloak was also captured);
- Login using challenge-response handshake;
- Usage of an API endpoint to check access control;
- Logout.

In this context, ```10.5.0.1``` is the user, ```10.5.0.5``` is the application and ```10.5.0.4``` is Keycloak. <br> <br>
If you want to do another capture, follow these steps:

- Uncomment the two lines in the ```Dockerfile``` to install ```tcpdump``` in the application's container;
- Uncomment the call to ```tcpdump``` in ```run.sh```;
- Set ```use_https``` to ```false``` in ```volume/config/config.json```;
- Change the following line in ```app.py```: ```app.config['SESSION_COOKIE_SECURE'] = True``` to ```app.config['SESSION_COOKIE_SECURE'] = False```;
- Refactor each Keycloak URL in ```volume/config/client_secrets.json``` so that the application contacts Keycloak with HTTP and not with HTTPS;
- At this point you are recording the communications between the application and Keycloak; to record the communications between the user and the application and between the user and Keycloak, from your (Linux) host machine issue the following command: ```tcpdump -i any host 10.5.0.5 or host 10.5.0.4 -w client.pcap```, use ```sudo``` if needed;

Now interact as you want, record the traffic, then stop everything; you may want to filter HTTP traffic from the pcaps, because there could be ARP requests and other network-level stuff. <br>
After you obtained your filtered traffic files, the last thing you may want to do is a ```mergecap cap_1.pcap cap_2.pcap -w full.pcap```. 
