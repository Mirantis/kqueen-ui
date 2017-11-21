from flask import (current_app as app, abort, Blueprint, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from kqueen_ui.api import get_kqueen_client
from slugify import slugify

from .forms import UserRegistrationForm

import logging

logger = logging.getLogger(__name__)

registration = Blueprint('registration', __name__, template_folder='templates')


def _get_client():
    username = app.config['KQUEEN_SERVICE_USER_NAME']
    password = app.config['KQUEEN_SERVICE_USER_PASSWORD']
    return get_kqueen_client(username=username, password=password)


@registration.route('/register', methods=['GET', 'POST'])
def register():
    form = UserRegistrationForm()
    if form.validate_on_submit():
        client = _get_client()

        try:
            organization = {
                'name': form.organization_name.data,
                'namespace': slugify(form.organization_name.data)
            }
            response = client.organization.create(organization)

            if response.status > 200:
                flash('Could not create organization.', 'danger')
                return render_template('registration/register.html', form=form)

            organization_id = response.data['id']
        except Exception as e:
            logger.error('user_create view: {}'.format(repr(e)))
            flash('Could not create organization.', 'danger')
            return render_template('registration/register.html', form=form)

        try:
            organization_ref = 'Organization:{}'.format(organization_id)
            user = {
                'username': form.username.data,
                'password': form.password_1.data,
                'email': form.email.data,
                'organization': organization_ref,
                'active': False
            }
            response = client.user.create(user)

            if response.status > 200:
                flash('Could not create user.', 'danger')
                client.organization.delete(organization_id)
                return render_template('registration/register.html', form=form)
        except Exception as e:
            logger.error('user_create view: {}'.format(repr(e)))
            client.organization.delete(organization_id)
            flash('Could not create user.', 'danger')
            return render_template('registration/register.html', form=form)

        flash('Registration successful. Check your e-mail for the activation link!', 'success')
        return redirect(url_for('ui.login'))

    return render_template('registration/register.html', form=form)
