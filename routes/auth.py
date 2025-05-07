from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db, oauth
from models import User, Role
import os

bp = Blueprint('auth', __name__)

# OAuth configuration
oauth_remote = oauth.remote_app(
    'azure',
    consumer_key=os.getenv('AZURE_CLIENT_ID'),
    consumer_secret=os.getenv('AZURE_CLIENT_SECRET'),
    request_token_params={'scope': 'openid email profile'},
    base_url='https://graph.microsoft.com/v1.0/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
)

@bp.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('credentials.index'))
    return render_template('auth/login.html')

@bp.route('/login/azure')
def azure_login():
    return oauth_remote.authorize(callback=url_for('auth.azure_callback', _external=True))

@bp.route('/login/azure/callback')
def azure_callback():
    resp = oauth_remote.authorized_response()
    if resp is None or resp.get('access_token') is None:
        flash('Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        ))
        return redirect(url_for('auth.login'))
    
    # Get user info from Microsoft Graph
    user_info = oauth_remote.get('me').data
    
    # Find or create user
    user = User.query.filter_by(email=user_info['mail']).first()
    if not user:
        user = User(
            email=user_info['mail'],
            name=user_info['displayName']
        )
        # Set a random password since we're using OAuth
        user.set_password(os.urandom(24).hex())
        
        # Assign default role
        default_role = Role.query.filter_by(name='user').first()
        if default_role:
            user.roles.append(default_role)
        
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    return redirect(url_for('credentials.index'))

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login')) 