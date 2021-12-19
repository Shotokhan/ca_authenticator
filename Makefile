build_all:
	docker-compose build

build:
	docker-compose build ca_authenticator
	
up:
	# docker stack deploy --orchestrator=swarm --compose-file=docker-compose.yml ca_authenticator_stack
	docker-compose up

start:
	docker-compose start
	
stop:
	docker-compose stop

down:
	docker-compose down ca_authenticator
	# docker stack rm --orchestrator=swarm ca_authenticator_stack
