from flask import url_for


def test_register(client, app):
    response = client.get(url_for('registration.register'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Registration</h2>' in html


def test_verify_email(client, app, email_token):
    response = client.get(url_for('registration.verify_email', token=email_token))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))
