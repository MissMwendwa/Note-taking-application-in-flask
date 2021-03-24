from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            
            else:
                flash('Opps!!try again', category='error')
        else:
            flash('Email is non-exixtent!', category='error')

    return render_template('login.html', user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('fist_name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

    user = User.query.filter_by(email=email).first_name()
    if user:
        flash('Email already exists!', category='error')
    elif len(email) < 4:
        flash('enter valid email', category='error')
    elif len(first_name) < 3:
        flash('Enter valid name', category='error')
    elif len('password') < 10:
        flash('Create stronger password', category='error')
    elif password != confirm_password:
        flash('Password must match!', category='error')
    else:
        new_user = User(email=email, first_name=first_name, password=generate_password_hash(
            password, method='gwhduudgilkhiqU28'
        ))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user, remember=True)
        flash('Welcome {new_user}', category='success')
        return redirected(url_for('views_home'))
return render_template("registration.html", user=current_user)
