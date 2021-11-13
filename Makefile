service=ca_authenticator_ca_authenticator_1


build_up:
	docker-compose up --build -d && docker attach "$(service)"
	
start:
	docker-compose start && docker attach "$(service)"
	
stop:
	docker-compose stop

