build_all:
	# because of permissions for MongoDB and Postgre
	sudo docker-compose build

build:
	# it still checks permissions -.-
	sudo docker-compose build ca_authenticator
	
up:
	docker-compose up
	
start:
	docker-compose start
	
stop:
	docker-compose stop

down:
	docker-compose down ca_authenticator

