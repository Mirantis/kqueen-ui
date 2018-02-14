from flask import request
from flask import redirect
from flask import session
from flask import url_for
from functools import wraps


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user', {}).get('id', None):
            return redirect(url_for('ui.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user', {}).get('id', None):
            return redirect(url_for('ui.login', next=request.url))
        elif session['user'].get('role', 'Member') != 'superadmin':
            return redirect(url_for('ui.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function
