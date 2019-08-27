from passzero.api import api
from flask import json

print(json.dumps(api.__schema__))
