"""
This module checks emailing functionality
Just make sure that we can send emails
It *really* sends the email, so the test is live
"""
import os

from passzero import email as pz_email
from passzero.my_env import SENDGRID_API_KEY, REAL_EMAIL


def test_send_email():
    os.environ["SENDGRID_API_KEY"] = SENDGRID_API_KEY
    success = pz_email.send_email(REAL_EMAIL, "hello world subject",
            "hello world body")
    assert success == True

