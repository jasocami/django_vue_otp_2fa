
ifeq ($(verbose),1)
  @echo "Notice: verbose mode requested."
  compose-flags+=--verbose
endif

# Vars

compose-flags+=--progress plain
stack-yml = ./devops/docker-compose.yaml
run-compose = docker compose $(compose-flags) -f $(stack-yml)

# Extras

-include ./aliases.mk

# Help

default: help

help:
	@echo "Usage: make <command> [verbose=1]"
	@echo "To get help about the available commands run the 'help' command."
	@echo "List of available commands:"
	@echo "up           Up all services"
	@echo "build        Build all services"
	@echo "build-no-cache         Build all services no cache"
	@echo "down         down all services"
	@echo "remove-volumes   compose remove all volumes"
	@echo "clean        compose down rmi all"
	@echo "clean-remove-volumes  compose rmi all and volumes"
	@echo "init         First start. Generate certificates, build and up "

# Commands

up:
	@echo "compose up all. Use CTRL+C to stop."
	$(run-compose) up

up/db:
	@echo "compose up all. Use CTRL+C to stop."
	$(run-compose) up db

up/backend:
	@echo "compose up all. Use CTRL+C to stop."
	$(run-compose) up backend

up/proxy:
	@echo "compose up all. Use CTRL+C to stop."
	$(run-compose) up proxy

up/web:
	@echo "compose up all. Use CTRL+C to stop."
	$(run-compose) up web

build:
	@echo "compose build all. Use CTRL+C to stop."
	$(run-compose) build

build-no-cache:
	@echo "compose build all. Use CTRL+C to stop."
	$(run-compose) build --no-cache

down:
	@echo "compose down all. Use CTRL+C to stop."
	$(run-compose) down

stop:
	@echo "compose stop all. Use CTRL+C to stop."
	$(run-compose) stop

remove-volumes:
	@echo "compose remove all volumes. Use CTRL+C to stop."
	$(run-compose) down -v

clean:
	@echo "compose down rmi all. Use CTRL+C to stop."
	$(run-compose) down --rmi all

clean-remove-volumes:
	@echo "compose rmi all and volumes. Use CTRL+C to stop."
	$(run-compose) down -v --rmi all

backend-test:
	$(run-compose) exec -it backend bash -c "python manage.py test"

renew-certs:
	curl --silent --show-error --location \
		--output /tmp/localhost.direct.zip https://aka.re/localhost
	unzip -o -u -P IWillNotPutKeyFileInPublicAccessiblePlace.X1YKK /tmp/localhost.direct.zip -d ./devops/

# https://github.com/Upinel/localhost.direct

renew-certs-new:
	rm -f \
		./devops/localhost.direct* \
		./devops/backloop.dev*
	curl --silent --show-error --location \
		--output /tmp/localhost.direct.zip https://aka.re/localhost
	unzip -o -u -P IWillNotPutKeyFileInPublicAccessiblePlace.X1YKK \
		/tmp/localhost.direct.zip -d ./devops/
	curl --silent --show-error --location \
	  --output ./devops/backloop.dev-ca.crt https://backloop.dev/backloop.dev-ca.crt
	curl --silent --show-error --location \
	  --output ./devops/backloop.dev-cert.crt https://backloop.dev/backloop.dev-cert.crt
	curl --silent --show-error --location \
	  --output ./devops/backloop.dev-key.pem https://backloop.dev/backloop.dev-key.pem
	ls ./devops/

start: renew-certs-new clone-env create-mailpit-folder build-no-cache up

clone-env:
	@echo "Clone env files"
	cp backend/env.example backend/.env

create-mailpit-folder:
	@echo "Create mailpit directories"
	mkdir data && mkdir data/mail/
