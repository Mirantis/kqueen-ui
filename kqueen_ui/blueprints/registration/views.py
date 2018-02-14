from datetime import datetime
from flask import Blueprint, current_app as app, flash, redirect, render_template, url_for
from flask_mail import Mail, Message
from kqueen_ui.auth import confirm_token, generate_confirmation_token
from kqueen_ui.exceptions import KQueenAPIException
from kqueen_ui.generic_views import KQueenView
from slugify import slugify

from .forms import UserRegistrationForm

import logging

logger = logging.getLogger('kqueen_ui')
mail = Mail()

registration = Blueprint('registration', __name__, template_folder='templates')


class Register(KQueenView):
    methods = ['GET', 'POST']

    def handle(self):
        if not app.config['ENABLE_PUBLIC_REGISTRATION']:
            flash('Public registration is disabled.', 'warning')
            return redirect(url_for('ui.index'))
        form = UserRegistrationForm()
        if form.validate_on_submit():
            organization_kw = {
                'name': form.organization_name.data,
                'namespace': slugify(form.organization_name.data),
                'created_at': datetime.utcnow()
            }
            organization = self.kqueen_request('organization', 'create', fnargs=(organization_kw,), service=True)
            organization_ref = 'Organization:{}'.format(organization['id'])
            user_kw = {
                'username': form.email.data,
                'password': form.password_1.data,
                'email': form.email.data,
                'organization': organization_ref,
                'role': 'admin',
                'created_at': datetime.utcnow(),
                'active': False
            }
            try:
                user = self.kqueen_request('user', 'create', fnargs=(user_kw,), service=True)
            except KQueenAPIException:
                self.kqueen_request('organization', 'delete', fnargs=(organization['id'],), service=True)
                return render_template('registration/register.html', form=form)

            # Init mail handler
            mail.init_app(app)
            token = generate_confirmation_token(user['email'])
            html = render_template('registration/email/verify_email.html', token=token)
            msg = Message(
                '[KQueen] E-mail verification',
                recipients=[user['email']],
                html=html
            )
            try:
                mail.send(msg)
            except Exception as e:
                self.logger('error', repr(e))
                self.kqueen_request('user', 'delete', fnargs=(user['id'],), service=True)
                self.kqueen_request('organization', 'delete', fnargs=(organization['id'],), service=True)
                flash('Could not send verification e-mail, please try again later.', 'danger')
                return render_template('registration/register.html', form=form)

            flash('Registration successful. Check your e-mail for the activation link!', 'success')
            return redirect(url_for('ui.login'))
        return render_template('registration/register.html', form=form)


class VerifyEmail(KQueenView):
    methods = ['GET']

    def handle(self, token):
        email = confirm_token(token)
        if not email:
            flash('Verification link is invalid or has expired.', 'danger')
            return redirect(url_for('ui.index'))

        users = self.kqueen_request('user', 'list', service=True)
        # TODO: this logic realies heavily on unique emails, this is not the case on backend right now
        filtered = [u for u in users if u.get('email', None) == email]
        if len(filtered) == 1:
            user = filtered[0]
            if user.get('active', None):
                flash('Account already verified. Please login.', 'success')
            else:
                user['active'] = True
                self.kqueen_request('user', 'update', fnargs=(user['id'], user), service=True)
                flash('You have confirmed your account. Thanks!', 'success')
        else:
            flash('No user found based on given e-mail.', 'danger')
        return redirect(url_for('ui.index'))


registration.add_url_rule('/register', view_func=Register.as_view('register'))
registration.add_url_rule('/verify/<token>', view_func=VerifyEmail.as_view('verify_email'))
