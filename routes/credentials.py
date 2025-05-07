from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db, secret_client
from models import Credential, User
from cryptography.fernet import Fernet
import base64
import os

bp = Blueprint('credentials', __name__)

def get_encryption_key():
    # Get encryption key from Azure Key Vault
    key = secret_client.get_secret('encryption-key')
    return base64.urlsafe_b64decode(key.value)

def encrypt_password(password):
    f = Fernet(get_encryption_key())
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    f = Fernet(get_encryption_key())
    return f.decrypt(encrypted_password.encode()).decode()

@bp.route('/')
@login_required
def index():
    credentials = current_user.credentials.all()
    shared_credentials = current_user.shared_credentials.all()
    return render_template('credentials/index.html', 
                         credentials=credentials,
                         shared_credentials=shared_credentials)

@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url')
        notes = request.form.get('notes')
        
        credential = Credential(
            name=name,
            username=username,
            encrypted_password=encrypt_password(password),
            url=url,
            notes=notes,
            user_id=current_user.id
        )
        
        db.session.add(credential)
        db.session.commit()
        
        flash('Credential created successfully!', 'success')
        return redirect(url_for('credentials.index'))
    
    return render_template('credentials/create.html')

@bp.route('/<int:id>')
@login_required
def view(id):
    credential = Credential.query.get_or_404(id)
    
    # Check if user has access
    if credential.user_id != current_user.id and current_user not in credential.shared_with:
        flash('You do not have access to this credential.', 'error')
        return redirect(url_for('credentials.index'))
    
    # Decrypt password for display
    credential.password = decrypt_password(credential.encrypted_password)
    return render_template('credentials/view.html', credential=credential)

@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    credential = Credential.query.get_or_404(id)
    
    if credential.user_id != current_user.id:
        flash('You do not have permission to edit this credential.', 'error')
        return redirect(url_for('credentials.index'))
    
    if request.method == 'POST':
        credential.name = request.form.get('name')
        credential.username = request.form.get('username')
        if request.form.get('password'):
            credential.encrypted_password = encrypt_password(request.form.get('password'))
        credential.url = request.form.get('url')
        credential.notes = request.form.get('notes')
        
        db.session.commit()
        flash('Credential updated successfully!', 'success')
        return redirect(url_for('credentials.view', id=credential.id))
    
    # Decrypt password for display
    credential.password = decrypt_password(credential.encrypted_password)
    return render_template('credentials/edit.html', credential=credential)

@bp.route('/<int:id>/share', methods=['GET', 'POST'])
@login_required
def share(id):
    credential = Credential.query.get_or_404(id)
    
    if credential.user_id != current_user.id:
        flash('You do not have permission to share this credential.', 'error')
        return redirect(url_for('credentials.index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('User not found.', 'error')
        elif user in credential.shared_with:
            flash('Credential is already shared with this user.', 'error')
        else:
            credential.shared_with.append(user)
            credential.is_shared = True
            db.session.commit()
            flash('Credential shared successfully!', 'success')
        
        return redirect(url_for('credentials.view', id=credential.id))
    
    return render_template('credentials/share.html', credential=credential)

@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    credential = Credential.query.get_or_404(id)
    
    if credential.user_id != current_user.id:
        flash('You do not have permission to delete this credential.', 'error')
        return redirect(url_for('credentials.index'))
    
    db.session.delete(credential)
    db.session.commit()
    flash('Credential deleted successfully!', 'success')
    return redirect(url_for('credentials.index')) 