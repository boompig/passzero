"""
This module checks emailing functionality
Just make sure that we can send emails
It *really* sends the email, so the test is live
"""
import os

from passzero import email as pz_email
from passzero.config import DefaultConfig
from passzero.my_env import REAL_EMAIL, SENDGRID_API_KEY


def test_send_email() -> None:
    os.environ["SENDGRID_API_KEY"] = SENDGRID_API_KEY
    # adding a bit more information to this email
    # in case I kick off the build by accident
    success = pz_email.send_email(
        REAL_EMAIL,
        "Live Test Local with build ID %s" % DefaultConfig.BUILD_ID,
        "Running local live test for build with ID %s" % DefaultConfig.BUILD_ID
    )
    assert success
