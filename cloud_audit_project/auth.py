from flask import Blueprint, redirect, url_for, session, flash
from functools import wraps
from oauth import google 

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login')
def login():
    return google.authorize_redirect(redirect_uri=url_for('auth.authorized', _external=True))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        jwt_token = session.get('jwt_token')
        if not jwt_token:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)

    return decorated_function

@auth_bp.route('/login/authorized')
def authorized():
    token = google.authorize_access_token()
    if token is None or 'access_token' not in token:
        flash('Access denied: Google login failed.')
        return redirect(url_for('auth.login'))

    userinfo = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
    email = userinfo.get('email')
    print(email)

    if not email.endswith('@strobes.co'):
        return redirect(url_for('auth.login'))

    session['user_info'] = userinfo
    session['jwt_token'] = token['access_token']

    return redirect(url_for('dashboard'))