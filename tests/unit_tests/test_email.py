from passzero import email
from mock import patch, MagicMock
import os


@patch.dict(os.environ, {}, clear=True)
def test_send_email_no_api_key():
    assert not email.send_email('a', 'b', 'c')


@patch.dict(os.environ, {"SENDGRID_API_KEY": "xxxxx"}, clear=True)
@patch("sendgrid.SendGridAPIClient")
def test_send_email_post_failed(m):
    """This tests whether we can return a sane value in the face of
    3rd party error"""
    m.side_effect = Exception("I am very bad at my job")
    assert not email.send_email('a', 'b', 'c')


@patch.dict(os.environ, {"SENDGRID_API_KEY": "xxxxx"}, clear=True)
@patch("passzero.email.sendgrid")
def test_send_email(m):
    # lots of mocking setup
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_client.client.mail.send.post.return_value = mock_response
    m.SendGridAPIClient.return_value = mock_client
    # this one will fail
    mock_response.status_code = 400
    assert not email.send_email('a', 'b', 'c')
    # this one will succeed
    mock_response.status_code = 200
    assert email.send_email('a', 'b', 'c')


@patch.dict(os.environ, {"SENDGRID_API_KEY": "xxxxx"}, clear=True)
# we have to patch request otherwise flask freaks out
@patch("passzero.email.request")
def test_send_recovery_email(m):
    with patch("passzero.email.send_email", return_value=True):
        assert email.send_recovery_email('a', 'b')
    with patch("passzero.email.send_email", return_value=False):
        assert not email.send_recovery_email('a', 'b')


@patch.dict(os.environ, {"SENDGRID_API_KEY": "xxxxx"}, clear=True)
# we have to patch request otherwise flask freaks out
@patch("passzero.email.request")
def test_send_confirmation_email(m):
    with patch("passzero.email.send_email", return_value=True):
        assert email.send_confirmation_email(u'fake_email@fake.com', u'tokentoken')
    with patch("passzero.email.send_email", return_value=False):
        assert not email.send_confirmation_email(u'fake_email@fake.com', u'tokentoken')
