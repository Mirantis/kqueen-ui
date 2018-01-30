from flask import jsonify
from flask import request
from flask import redirect
from flask import session
from flask import url_for
from functools import wraps


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user', {}).get('id', None):
            is_json = request.headers['Accept'] == 'application/json'
            if is_json:
                data = {
                    'response': 301,
                    'redirect': url_for('ui.login')
                }
                return jsonify(data)
            return redirect(url_for('ui.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function
