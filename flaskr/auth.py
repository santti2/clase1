import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        checkeo = request.form['checkeo']
        email = request.form['email']
        db = get_db()
        error = None

        if not username:
            error = 'se requiere el usuario.'
        elif not password:
            error = 'se requiere contrasenia.'
        elif password  != checkeo:
            error = 'la contraseña no coincide .'
        elif not email:
            error = 'se requiere el email'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password, email) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), email),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered"
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

@bp.route('/update', methods=('GET', 'POST'))
@login_required

def updateemail():
    if request.method == 'POST':
        newemail = request.form['email']
        newemail2 = request.form['email2']
        error = None

        if not newemail:
            error = 'se requiere nuevo email'
        elif "@" not in newemail:
            error = 'no es un  email'
        elif newemail != newemail2:
            error = 'los emails no coinciden'
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE user SET email = ?'
                ' WHERE id = ?',
                (newemail, g.user["id"])
            )
            db.commit()
            return redirect(url_for('blog.index'))
    
    return render_template('auth/email.html', user = g.user)

