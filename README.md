# PassZero

[![Travis Build Status](https://travis-ci.org/boompig/passzero.svg?branch=master)](https://travis-ci.org/boompig/passzero)
[![Coverage Status](https://coveralls.io/repos/github/boompig/passzero/badge.svg?branch=master)](https://coveralls.io/github/boompig/passzero?branch=master)

## About

PassZero is a secure password manager implemented in Python. It is accessible in the browser and can be run either locally or remotely.

## Design

PassZero is implemented as a simple web app with results held in a database, the frontend is presented as HTML in the browser, and the server is implemented in Python (Flask). All of the crypto happens server-side.

## Running Locally

### Docker

build:

```
docker compose build
```

run:

First edit `docker-compose.yml` and change the environment variable `SENDGRID_API_KEY` and `DATABASE_URL`.

```
docker compose up
```

### Local Machine

* install postgres
    - on some platforms it may be necessary to install python bindings at the system level
* install the following packages if not present:
    - python-dev
    - libssl-dev
    - postgresql-server-dev
* create virtualenv from requirements.txt
* if running on Mac, install certificates using [this procedure](https://stackoverflow.com/a/10176685)
* create self-signed certificate for SSL, place it at root of PassZero
    - instructions [here](https://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl)
* set environment variables
    - `FLASK_ENV` - recommended to set this explicitly to "production" when running in a production capacity
    - `DATABASE_URL`
        - `postgres://<username>:<password>@<host>:<port>/<database>`
    - `SENDGRID_API_KEY`
    - `REAL_EMAIL` (testing only)
    - alternatively create file `.env` with environment variable values from above. This file will be loaded using the dotenv package
* `heroku local web`

## Development

All instructions in "running locally", as well as:

- install nodejs and npm
- `make install`

There is limited support for running the server without an internet connection. Some parts of the site may not work, but if you set `OFFLINE=1` as an environment variable then portions of the site take that into account and try to work anyway.

If you want to run without HTTPS you can set the environment variable `NO_SSL=1`

The default flask server will always create database tables. If you want the gunicorn instantiation to create the tables, specify `GUNICORN_CREATE_TABLES=1`.

### Building React Components

Most of the client-side components are written using React. You need to re-compile the react bundle for each page after modifying. Run this command:

```
yarn build
```

### Changing CSS

Most CSS is not included in the respective bundles.
When modifying the CSS you have to rebuild the minified CSS using the command:

```
make minify-css
```

### Running Unit Tests

`make test`

## Deploying

* run `make` to generate new build ID so caches are invalidated for old CSS and JS resources
    - can also just run `make build-name`
* deploy to server

## License

* GPLv3
