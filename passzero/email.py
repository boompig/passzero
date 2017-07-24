from __future__ import print_function
from flask import request
import logging
import os
import sys
from sendgrid.helpers.mail import Email, Content, Mail
import sendgrid


def send_email_sendgrid(to_email, subject, msg):
    """Directly taken from sendgrid site code sample"""
    try:
        assert os.environ.get("SENDGRID_API_KEY", None)
    except AssertionError:
        print("SENDGRID_API_KEY not found in env", file=sys.stderr)
        return False
    try:
        sg = sendgrid.SendGridAPIClient(apikey=os.environ['SENDGRID_API_KEY'])
        from_email = Email("noreply@passzero.local")
        mail = Mail(from_email, subject, Email(to_email),
            Content("text/plain", msg))
        response = sg.client.mail.send.post(request_body=mail.get())
    except Exception as e:
        logging.error("Failed to send email:")
        logging.error(e)
        return False
    if response.status_code in [200, 202]:
        return True
    else:
        # log errors before returning false
        logging.error("status code = %d", response.status_code)
        logging.error("response body = %s", response.body)
        logging.error("response headers = %s", str(response.headers))
        return False

def send_email(email, subject, msg):
    return send_email_sendgrid(email, subject, msg)

def send_recovery_email(email, token):
    link =  request.url_root + "recover/confirm?token=%s" % token
    return send_email(
        email,
        "Recover your PassZero account",
        "To complete your PassZero account recovery, follow this link: %s" % link
    )

def send_confirmation_email(email, token):
    link =  request.url_root + "signup/confirm?token=%s" % token
    return send_email(
        email,
        "Thanks for signing up for PassZero",
        "To complete your PassZero signup, follow this link: %s" % link
    )
