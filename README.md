# ca_authenticator
<br>
The idea is the following:

- Create a self-signed certificate, making the server a CA;
- Create a server certificate using the CA's certificate;
- Have an HTTPS endpoint to create client certificates: they can be created with user-provided input for testing, but the actual client certificates will be issued according to an identity assurance procedure, leveraging 3rd party authentication;
- Have another HTTPS endpoint for the real application, which requires client authentication with certificates issued by the previously mentioned endpoint, and uses X.509 extensions for identification and for role association; the access control is handled by 3rd party.

Private keys are encrypted: when you start the application using ```ca_auth_makefile```, you press Enter and then you have a prompt for the server's key and a prompt for the CA's key. You can generate new certificates using ```certificates_library.py```. <br>
Certificates' input data is conveniently managed using JSON files, look at ```/volume``` subfolder. <br> <br>
You can start the entire network for the application using ```docker-compose.yml```, which uses docker secrets to provide passwords and other secrets to the containers; every secret you may want to change is in ```/secrets``` folder, which will not be copied in any container (it is only accessible by the host). <br>
The two HTTPS endpoints were coalesced into a single one. The 3rd party authentication is enforced using Keycloak which uses Postgres as backend. <br>
Keycloak is also used for policy enforcement (it has PEP, PDP, PAP and PIP). <br>
This is like a Self-Sovereign Identity architecture, where Keycloak is the Issuer, the application is the Verifier and the client's browser is the Holder. <br>

# Configuration instructions
As utility, we exported our Keycloak realm into a file, but you may want to create a new one from scratch. <br>
The steps to follow in Keycloak are the following:

1) Create a new realm, for example ```flask-demo```;
2) Into project, open ```/volume/config/client_secrets.json``` and change any URL according to the new realm name, for example ```https://10.5.0.4:8443/auth/realms/flask-demo``` to ```https://10.5.0.4:8443/auth/realms/your_new_realm```;
3) In your new realm, create a new client, for example ```flask-app```;
4) Go to Clients -> ```<Your new client>``` -> Settings -> Authentication Flow Overrides and select ```browser``` for Browser Flow and ```direct grant``` for Direct Grant Flow;
5) Go to Clients -> ```<Your new client>``` -> Credentials and select ```Client Id and Secret``` as Client Authenticator, then Regenerate Secret;
6) Into project, open ```/volume/config/client_secrets.json``` and set ```client_id``` field to the name of your new client, then open ```/secrets/ca_auth.env``` and  set ```client_secret``` to the generated secret;
7) Go to Roles -> Add Role for two times to create new realm roles, ```student``` and ```teacher```;
8) Go to Clients -> ```<Your new client>``` -> Roles -> Add Role to create new client roles: ```book-exam```, ```confirm-exam```, ```publish-exam```, ```view-exam```, ```view-grade```;
9) Go to Client Scopes -> Roles -> Mappers -> Realm Roles and switch to On all of: ```Add to ID token```, ```Add to access token```, ```Add to userinfo```, this is to make the application access the claims;
10) Go to Client Scopes -> Roles -> Mappers -> Client Roles and switch to On all of: ```Add to ID token```, ```Add to access token```, ```Add to userinfo```;
11) Now it's time to make the mapping between Realm Roles and Client Roles.
    
    - Go to Roles -> ```student``` -> Composite Roles -> Client Roles, select ```<Your new client>``` and select ```book-exam```, ```view-exam```, and ```view-grade``` from Available Roles to make them Associated Roles; 
    - Go to Roles -> ```teacher``` -> Composite Roles -> Client Roles, select ```<Your new client>``` and select ```confirm-exam``` and ```publish-exam``` from Available Roles to make them Associated Roles;
12) Go to Users -> Add User and specify at least the Username (for example 'prova' if you want to run ```test_client.py```), leaving On the tick for ```User Enabled```;
13) Go to Users -> ```<Your new user>``` -> Credentials and set a non-temporary password (for the user 'prova' the password should be 'prova' to run the test);
14) Go to Users -> ```<Your new user>``` -> Role Mappings -> Realm Roles and select a role from Available Roles to make it an Assigned Role (```student``` for the user 'prova'), now if you open, in the same window, Client Roles -> ```<Your new client>``` you can see that the user has the Effective Roles assigned to the Client Roles mapped to the Composite Realm Role assigned to it;
15) Repeat .12, .13 and .14 for an user with realm role ```teacher```;
16) Go to Clients -> ```<Your new client>``` -> Settings and tick ```Authorization enabled``` to On;
17) Go to Clients -> ```<Your new client>``` -> Authorization and do the following:

    - Go to Authorization Scopes and Create a scope called ```do```;
    - Go to Resources and create a resource for each client role: ```book-exam```, ```view-exam```, ```view-grade```, ```confirm-exam```, ```publish-exam```;
    - Go to Policies and create a policy for each realm role: ```student``` and ```teacher```;
    - Go to Permissions and create a permission for each mapping between realm roles and client roles, for example ```student_view_exam``` in which you select ```view-exam``` as resource and ```student``` as apply policy, with Unanimous decision strategy;
    - Optionally, go to Evaluate to check if you wrote policies well; now we're able to perform access control using Keycloak as PEP, and we can write more complex policies than a simple mapping between realm roles and client roles.
18) Optionally, go to Realm Settings -> Security Defenses -> Brute Force Detection and enable it;
19) Optionally, go to Authentication -> Flows and set ```Browser - Conditional OTP``` as Required: at the first login, you will have to configure OTP by scanning a QR Code, for example with FreeOTP app; note that if you configure this option, you can't use ```test_client.py``` anymore.

At this point, you may want to re-spawn CA certificate and server certificate. The related fields can be changed in ```/volume/ca_data.json``` and ```/volume/server_data.json```, although they're not very crucial for the application. <br>
If you run ```certificates_library.py``` in the root directory of the project, you have prompts about the passphrases to use for encrypting CA and server's private keys and some informations about file locations (by default they are written in the ```/test``` folder). You have to move the generated files in the ```/volume``` folder, and change the environment values ```CAPass``` and ```serverPass``` in ```/secrets/ca_auth.env``` file. <br>
We also suggest you to change all the other default passwords and secrets in ```/secrets``` folder. <br> <br>
The last thing to configure is ```/volume/config/config.json```:

- the ```app``` section is related to the Flask app, which is OIDC-extended, you have to set ```OIDC_OPENID_REALM``` to ```<Your Keycloak realm>```, check Flask and flask-oidc docs for the other parameters, but leave at least "profile" and "roles" in ```OIDC_SCOPES```;
- the ```misc``` section is related to some application parameters:
    + ```nonce_list_lim``` is the maximum number of nonces the server can store for challenge-response handshakes before re-spawning the app's secret key;
    + ```disable_ssl_verification_for_oauth2``` should be set to false only if Keycloak's certificate is a worldwide valid certificate;
    + ```max_validity_days``` is the maximum number of validity days for client certificates;
    + ```use_https``` tell the app if to run on HTTPS or not;
- the ```rest_resources``` section contains mapping between resources, intended as client roles, and REST API endpoints: it's just for the interface.

Now you're ready to start the application.
