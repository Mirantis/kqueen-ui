from flask import url_for


def test_register_get(client, app):
    response = client.get(url_for('registration.register'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Registration</h2>' in html


def test_register_post(client):
    form_data = {
        'organization_name': 'SomeOrganization',
        'email': 'someone@someorganization.com',
        'password_1': 'somepassword',
        'password_2': 'somepassword'
    }
    response = client.post(url_for('registration.register'), data=form_data)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.login'))


def test_verify_email(client, app, email_token):
    response = client.get(url_for('registration.verify_email', token=email_token))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))
