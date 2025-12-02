# OTP 2FA

Basic project where you have a 2FA verification code login with sent throw email.
The Auth token is controlled by JWT tokens.

## Technologies

This project is running on Docker backend, PostgreSQL, local email service, and a DB web viewer.

The package management is managed by poetry.

* Django: 5.1>
* Djangorestframework: 3.15>
* Djangorestframework-simplejwt: 5.3>
* Drf-spectacular: 0.27>
* Pyotp: 2.9>


## First Run

You can execute one command to execute the next steps with:

```bash
make start
```

This will:

* Download tls certs
* Clone env files
* Create mailpit folders 
* Docker build docker with no cache 
* Docker up

### Env

First clone the .env files

```bash
make clone-env
```

And edit the file with your required values

### Mailpit

Create a folder for Mailpit to save his database

```bash
make create-mailpit-folder
```

### Build docker

```bash
make build && make up
```

This will:

* Download certificates for caddy proxy (todo list)
* build docker with no cache mode
* Up all docker services

## Access

List of urls of access to different docker services:

* Backend: [http://localhost:8000](http://localhost:8000)
* Backend Swagger: [http://localhost:8000/schema/swagger/](http://localhost:8000/schema/swagger/)
* Backend redoc: [http://localhost:8000/schema/redoc/](http://localhost:8000/schema/redoc/)
* DB web UI: [http://localhost:5051](http://localhost:5051)
* Email (mailpit): [http://localhost:8025](http://localhost:8025)

## UnitTest

To run the unitTests you only need to first up services and then execute tests

```bash
make backend/test
```