# PassZero

## About

PassZero is a secure password manager implemented in Python. It is accessible in the browser and can be run either locally or remotely. All data can be stored in an sqlite database

PassZero is powered by the following technologies:

    * Twitter Bootstrap
    * Python Flask
    * gunicorn
    * wtforms
    * jQuery
    * Postgres
    * ~~sqlite3~~
    * pyCrypto

## Design

PassZero is implemented as a simple web app with results held in a database, the frontend is presented as HTML in the browser, and the server is implemented in Python (Flask). All of the crypto happens server-side.

## Running Locally

* create virtualenv from requirements.txt
* create self-signed certificate for SSL, place it at root of PassZero
* `foreman start local`
