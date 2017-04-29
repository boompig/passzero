web: NEW_RELIC_CONFIG_FILE=newrelic.ini newrelic-admin run-program gunicorn server:app --log-file -
local: gunicorn -w3 --certfile=cert.pem --keyfile=key.pem server:app --log-file -
