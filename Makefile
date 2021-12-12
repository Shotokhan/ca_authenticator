build_all:
	docker-compose build

build:
	docker-compose build ca_authenticator
	
up:
	docker-compose up
	
start:
	docker-compose start
	
stop:
	docker-compose stop

down:
	docker-compose down ca_authenticator

