import logging
import os
import sys

import sendgrid
from flask import request
from sendgrid.helpers.mail import Mail


# NOTE: we may note be working inside an app context here
logger = logging.getLogger(__name__)


def send_email_sendgrid(to_email: str, subject: str, msg: str) -> bool:
    """Directly taken from sendgrid site code sample"""
    assert isinstance(to_email, str)
    assert isinstance(subject, str)
    assert isinstance(msg, str)
    try:
        assert os.environ.get("SENDGRID_API_KEY", None)
    except AssertionError as err:
        print("SENDGRID_API_KEY not found in env", file=sys.stderr)
        logger.error("SENDGRID_API_KEY not found in env")
        logger.error(err)
        return False
    try:
        sg = sendgrid.SendGridAPIClient(os.environ['SENDGRID_API_KEY'])
        from_email = "PassZero <noreply@passzero.local>"
        message = Mail(
            from_email=from_email,
            subject=subject,
            to_emails=to_email,
            plain_text_content=msg
        )
        response = sg.send(message)
    except Exception as e:
        logger.error("Failed to send email:")
        logger.error(str(e))
        return False
    if response.status_code in [200, 202]:
        return True
    else:
        # log errors before returning false
        logger.error("status code = %d", response.status_code)
        logger.error("response body = %s", response.body)
        logger.error("response headers = %s", str(response.headers))
        return False


def send_email(email: str, subject: str, msg: str) -> bool:
    return send_email_sendgrid(email, subject, msg)


def send_recovery_email(email: str, token: str) -> bool:
    link = request.url_root + "recover/confirm?token=%s" % token
    return send_email(
        email,
        "Recover your PassZero account",
        "To complete your PassZero account recovery, follow this link: %s" % link
    )


def send_confirmation_email(email: str, token: str) -> bool:
    """Send an email to the user with a link to confirm the activation of their account.
    :param token: A random string that will be checked by the server. It has an expiry time.
    """
    link = request.url_root + "signup/confirm?token=%s" % token
    return send_email(
        email,
        "Thanks for signing up for PassZero",
        "To complete your PassZero signup, follow this link: %s" % link
    )
