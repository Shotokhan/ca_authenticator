# ca_authenticator
<br>
The idea is the following:

- Create a self-signed certificate, making the server a CA;
- Create a server certificate using the CA's certificate;
- Have an HTTPS endpoint to create client certificates: they can be created with user-provided input for testing, but the actual client certificates will be issued according to an identity assurance procedure, leveraging 3rd party authentication;
- Have another HTTPS endpoint for the real application, which requires client authentication with certificates issued by the previously mentioned endpoint, and uses X.509 extensions for identification and for role association: therefore, this endpoint will also enforce access control using X.509 data.

Private keys are encrypted: when you start the application using ca_auth_makefile, you press Enter and then you have a prompt for the server's key and a prompt for the CA's key. You can generate new certificates using certificates_library. <br>
Certificates' input data is conveniently managed using JSON files, look at /volume subfolder. <br> <br>
You can start the entire network for the application using docker-compose.yml, which has some hard-coded passwords which you may want to change in production. <br>
The two HTTPS endpoints were coalesced into a single one. The 3rd party authentication is enforced using Keycloak which uses Postgres as backend. Our application uses MongoDB as backend to store the mappings between roles and resources. <br>
