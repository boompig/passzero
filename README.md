# PassZero

[![Travis Build Status](https://travis-ci.org/boompig/passzero.svg?branch=master)](https://travis-ci.org/boompig/passzero)
[![Coverage Status](https://coveralls.io/repos/github/boompig/passzero/badge.svg?branch=master)](https://coveralls.io/github/boompig/passzero?branch=master)

## About

PassZero is a secure password manager implemented in Python. It is accessible in the browser and can be run either locally or remotely.

## Design

PassZero is implemented as a simple web app with results held in a database, the frontend is presented as HTML in the browser, and the server is implemented in Python (Flask). All of the crypto happens server-side.

## Running Locally

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
    - `DATABASE_URL`
        - `postgres://<username>:<password>@<host>:<port>/<database>`
    - `SENDGRID_API_KEY`
    - alternatively create file `passzero/my_env.py` with method `setup_env` which sets above environment variables
* `foreman start local`

## Development

All instructions in "running locally", as well as:

- install nodejs and npm
- `make install`

Your secret environment file (`passzero/my_env.py`) should look like this:

```
import os


DATABASE_URL = "<your database URL here>"
REAL_EMAIL = "<your real email here>
SENDGRID_API_KEY = "<your real SendGrid API key here>"


def setup_env():
    os.environ["DATABASE_URL"] = DATABASE_URL
    os.environ["REAL_EMAIL"] = REAL_EMAIL
    os.environ["SENDGRID_API_KEY"] = SENDGRID_API_KEY

```

### Building React Components

Most of the client-side components are written using React. You need to re-compile the react bundle for each page after modifying. Run this command:

```
yarn run webpack
```

### Changing CSS

Most CSS is not included in the respective bundles.
When modifying the CSS you have to rebuild the minified CSS using the command:

```
make minify-css
```

## Deploying

* run `make` to generate new build ID so caches are invalidated for old CSS and JS resources
* deploy to server

## License

* GPLv3
