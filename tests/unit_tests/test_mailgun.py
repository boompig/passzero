from passzero import mailgun
from mock import patch, MagicMock 
import os

@patch.dict(os.environ, {}, clear=True)
def test_send_email_no_api_key():
    assert mailgun.send_email('a', 'b', 'c') == False


@patch.dict(os.environ, { "MAILGUN_API_KEY": "xxxxx" }, clear=True)
@patch("requests.post")
def test_send_email_post_failed(m):
    m.side_effect = Exception("I am very bad at my job")
    assert mailgun.send_email('a', 'b', 'c') == False


@patch.dict(os.environ, { "MAILGUN_API_KEY": "xxxxx" }, clear=True)
@patch("requests.post")
def test_send_email(m):
    rval = MagicMock()
    rval.ok = True
    m.return_value = rval
    assert mailgun.send_email('a', 'b', 'c') == True
    rval.ok = False
    assert mailgun.send_email('a', 'b', 'c') == False


@patch.dict(os.environ, { "MAILGUN_API_KEY": "xxxxx" }, clear=True)
@patch("passzero.mailgun.request")
def test_send_recovery_email(m):
    with patch("passzero.mailgun.send_email", return_value=True):
        assert mailgun.send_recovery_email('a', 'b') == True
    with patch("passzero.mailgun.send_email", return_value=False):
        assert mailgun.send_recovery_email('a', 'b') == False


@patch.dict(os.environ, { "MAILGUN_API_KEY": "xxxxx" }, clear=True)
@patch("passzero.mailgun.request")
def test_send_confirmation_email(m):
    with patch("passzero.mailgun.send_email", return_value=True):
        assert mailgun.send_confirmation_email(u'fake_email@fake.com', u'tokentoken') == True
    with patch("passzero.mailgun.send_email", return_value=False):
        assert mailgun.send_confirmation_email(u'fake_email@fake.com', u'tokentoken') == False
