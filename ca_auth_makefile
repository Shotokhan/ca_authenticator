service=ca_authenticator_ca_authenticator_1


build_up:
	docker-compose -f ca_auth-docker-compose.yml up --build -d && docker attach ca_authenticator_ca_authenticator_1
	
start:
	docker-compose -f ca_auth-docker-compose.yml start && docker attach ca_authenticator_ca_authenticator_1
	
stop:
	docker-compose -f ca_auth-docker-compose.yml stop

