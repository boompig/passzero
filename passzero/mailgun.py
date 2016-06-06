from __future__ import print_function
from flask import request
import os
import requests

MAILGUN_URL = "https://api.mailgun.net/v2/sandbox59e35b39818642c28107668b360d1284.mailgun.org"
MAILGUN_EMAIL = "postmaster@sandbox59e35b39818642c28107668b360d1284.mailgun.org"

def _send_mailgun_email(email, subject, msg):
    try:
        API_KEY = "key-%s" % os.environ["MAILGUN_API_KEY"]
    except KeyError as e:
        assert e == "MAILGUN_API_KEY"
        print("MAILGUN_API_KEY not found in env")
        # MAILGUN_API_KEY not in envs
        return False
    payload = {
        "from": "PassZero <%s>" % MAILGUN_EMAIL,
        "to": email,
        "subject": subject,
        "text": msg
    }
    r = requests.post(
        MAILGUN_URL + "/messages",
        data=payload,
        auth = ("api", API_KEY)
    )
    return r.ok

def send_recovery_email(email, token):
    link =  request.url_root + "recover/confirm?token=%s" % token
    return _send_mailgun_email(
        email,
        "Recover your PassZero account",
        "To complete your PassZero account recovery, follow this link: %s" % link
    )

def send_confirmation_email(email, token):
    link =  request.url_root + "signup/confirm?token=%s" % token
    return _send_mailgun_email(
        email,
        "Thanks for signing up for PassZero",
        "To complete your PassZero signup, follow this link: %s" % link
    )
