web: NEW_RELIC_CONFIG_FILE=newrelic.ini newrelic-admin run-program gunicorn passzero:app --log-file -
local: gunicorn -w3 --certfile=server.crt --keyfile=server.key passzero:app --log-file -
