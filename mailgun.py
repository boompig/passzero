import os
import requests

MAILGUN_URL = "https://api.mailgun.net/v2/sandbox59e35b39818642c28107668b360d1284.mailgun.org"
MAILGUN_EMAIL = "postmaster@sandbox59e35b39818642c28107668b360d1284.mailgun.org"

def send_confirmation_email(email):
    if "MAILGUN_API_KEY" in os.environ:
        API_KEY = "key-%s" % os.environ["MAILGUN_API_KEY"]
        payload = {
            "from": MAILGUN_EMAIL,
            "to": email,
            "subject": "Thanks for signing up for PassZero",
            "text": "You're pretty great"
        }
        r = requests.post(
            MAILGUN_URL + "/messages",
            data=payload,
            auth = ("api", API_KEY)
        )
        return r.ok
    else:
        # means we're on localhost, so it's OK
        return True

if __name__ == "__main__":
    send_confirmation_email("dbkats@gmail.com")
