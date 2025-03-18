FROM python:3.13-slim-bullseye

# just for build - make sure packages aren't trying to do interactive installs
ARG DEBIAN_FRONTEND=noninteractive

# first need to install nodejs and yarn
RUN apt-get update -y && apt-get install -y curl
RUN curl -fsSL https://deb.nodesource.com/setup_22.x -o nodesource_setup.sh && \
    bash nodesource_setup.sh && \
    apt-get install -y nodejs
RUN npm install -y --global yarn
# Note that build tools like make and gcc are required to build some of the python packages
# libpq-dev is required for psycopg2
RUN apt-get install -y libpq-dev make gcc libffi-dev libsodium-dev

WORKDIR /work

# copy in requirements.txt first (python deps)
COPY requirements.txt /work
RUN pip install -r requirements.txt

# copy in the package.json next (node.js deps)
COPY package.json /work
RUN yarn

# then copy in the rest of the app
COPY . /work

# build client-side deps
RUN yarn heroku-postbuild

# create the log file directories if they do not exist
# however they should be host-mounted so it's easier to read out logs
RUN [ ! -d "/var/log/passzero" ] && mkdir -p /var/log/passzero && chmod -R og+rw /var/log/passzero

EXPOSE 8000
CMD ["gunicorn", "server:app", "--log-file", "-", "--bind", "0.0.0.0:8000"]
#, \
    # "--access-logfile", "/var/log/passzero/access.log", \
    # "--error-logfile", "/var/log/passzero/error.log"]