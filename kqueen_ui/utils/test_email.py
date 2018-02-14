import pytest

from .email import EmailMessage


def test_email_send(app, user):
    html = '<h3>Foo</h3>'
    email = EmailMessage(
        '[KQueen] Test E-Mail',
        recipients=[user['email']],
        html=html
    )
    email.send()
