FROM python:3.11-buster

# just for build - make sure packages aren't trying to do interactive installs
ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /work

# copy in requirements.txt first
COPY requirements.txt /work
RUN pip install -r requirements.txt

# then copy in the rest of the app
COPY . /work

# build client-side deps
# first need to install nodejs
RUN curl -fsSL https://deb.nodesource.com/setup_19.x | bash - && \
    apt-get install -y nodejs
# RUN apt-get update -y && apt-get install -y nodejs npm
RUN npm install -y --global yarn
RUN yarn && yarn heroku-postbuild

EXPOSE 8000
CMD ["gunicorn", "server:app", "--log-file", "-", "--bind", "0.0.0.0:8000"]