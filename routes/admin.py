from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from models import User, Role
from functools import wraps

bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not any(role.name == 'admin' for role in current_user.roles):
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('credentials.index'))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/')
@login_required
@admin_required
def index():
    users = User.query.all()
    roles = Role.query.all()
    return render_template('admin/index.html', users=users, roles=roles)

@bp.route('/users')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@bp.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.is_active = bool(request.form.get('is_active'))
        
        # Update roles
        user.roles = []
        for role_id in request.form.getlist('roles'):
            role = Role.query.get(role_id)
            if role:
                user.roles.append(role)
        
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin.users'))
    
    roles = Role.query.all()
    return render_template('admin/edit_user.html', user=user, roles=roles)

@bp.route('/roles')
@login_required
@admin_required
def roles():
    roles = Role.query.all()
    return render_template('admin/roles.html', roles=roles)

@bp.route('/roles/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_role():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if Role.query.filter_by(name=name).first():
            flash('Role with this name already exists.', 'error')
        else:
            role = Role(name=name, description=description)
            db.session.add(role)
            db.session.commit()
            flash('Role created successfully!', 'success')
            return redirect(url_for('admin.roles'))
    
    return render_template('admin/create_role.html')

@bp.route('/roles/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_role(id):
    role = Role.query.get_or_404(id)
    
    if request.method == 'POST':
        role.name = request.form.get('name')
        role.description = request.form.get('description')
        db.session.commit()
        flash('Role updated successfully!', 'success')
        return redirect(url_for('admin.roles'))
    
    return render_template('admin/edit_role.html', role=role)

@bp.route('/roles/<int:id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_role(id):
    role = Role.query.get_or_404(id)
    
    if role.name in ['admin', 'user']:
        flash('Cannot delete system roles.', 'error')
    else:
        db.session.delete(role)
        db.session.commit()
        flash('Role deleted successfully!', 'success')
    
    return redirect(url_for('admin.roles')) 