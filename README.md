# PassZero

[![Travis Build Status](https://travis-ci.org/boompig/passzero.svg?branch=master)](https://travis-ci.org/boompig/passzero)
[![Coverage Status](https://coveralls.io/repos/github/boompig/passzero/badge.svg?branch=master)](https://coveralls.io/github/boompig/passzero?branch=master)

## About

PassZero is a secure password manager implemented in Python. It is accessible in the browser and can be run either locally or remotely.

## Design

PassZero is implemented as a simple web app with results held in a database, the frontend is presented as HTML in the browser, and the server is implemented in Python (Flask). All of the crypto happens server-side.

## Running Locally

* create virtualenv from requirements.txt
* create self-signed certificate for SSL, place it at root of PassZero
* `foreman start local`

## Deploying

* run `make` to generate new build ID so caches are invalidated for old CSS and JS resources
* deploy to server

## License

* GPLv3
