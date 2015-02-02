from flask import request
import os
import requests

MAILGUN_URL = "https://api.mailgun.net/v2/sandbox59e35b39818642c28107668b360d1284.mailgun.org"
MAILGUN_EMAIL = "postmaster@sandbox59e35b39818642c28107668b360d1284.mailgun.org"

def send_confirmation_email(email, token):
    link =  request.url_root + "signup/confirm?token=%s" % token

    try:
        API_KEY = "key-%s" % os.environ["MAILGUN_API_KEY"]
        payload = {
            "from": "PassZero <%s>" % MAILGUN_EMAIL,
            "to": email,
            "subject": "Thanks for signing up for PassZero",
            "text": "To complete your PassZero signup, follow this link: %s" % link
        }
        r = requests.post(
            MAILGUN_URL + "/messages",
            data=payload,
            auth = ("api", API_KEY)
        )
        return r.ok
    except KeyError as e:
        assert e == "MAILGUN_API_KEY"
        print "MAILGUN_API_KEY not found in env"
        # MAILGUN_API_KEY not in envs
        return False

if __name__ == "__main__":
    send_confirmation_email("dbkats@gmail.com")
