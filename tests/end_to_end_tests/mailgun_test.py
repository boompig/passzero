"""
This module checks mailgun functionality
Just make sure that we can send emails
It *really* sends the email, so the test is live
"""
import os

from passzero import mailgun
from passzero.my_env import MAILGUN_API_KEY, REAL_EMAIL


def test_send_email():
    os.environ["MAILGUN_API_KEY"] = MAILGUN_API_KEY
    email = REAL_EMAIL
    success = mailgun.send_email(email, "hello world subject",
            "hello world body")
    assert success == True

