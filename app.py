from flask import Flask, render_template, url_for, flash, redirect, abort, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, \
                        login_required, current_user, logout_user, fresh_login_required
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from random import randint
from smtplib import SMTPException
from datetime import timedelta
import datetime
import time
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from creds import creds

from RPi import GPIO
from time import sleep

SESSION_TIME = 1 # minutes

# store user: code in the most retarded way possible
double_verificator = {}

# generate random digit code n-length
def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

app = Flask(__name__)

# delete user's code from dict
def del_user_from_dict():
    try:
        del double_verificator[current_user.username]
    except KeyError:
        pass

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=SESSION_TIME)


# pass hasher
bcrypt = Bcrypt(app)

# DB stuff
###################################################################
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = '5up3r pas5'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String)


# Gmail stuff
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = creds["login"] # TODO
app.config['MAIL_PASSWORD'] = creds["password"] # TODO
mail = Mail(app)


# reCAPTCHA
app.config['RECAPTCHA_PUBLIC_KEY'] = "6LdGOaEUAAAAAKgigjAsBM69n5A6E09JrOMlc6cd"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6LdGOaEUAAAAAKAFI8d50rswOxvxtzb74d3nzO_8"

# login stuff
###################################################################
class LoginForm(FlaskForm):
    username = StringField('Логин',
                        validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить')
    submit = SubmitField('Увійти')
    # recaptcha = RecaptchaField()

class Double(FlaskForm):
    code = StringField('Код з пошти',
                        validators=[DataRequired()])
    submit = SubmitField('Підтвердити')

class RegistrationForm(FlaskForm):
    username = StringField('Ім&#39я користувача',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Пароль ще раз',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Підтвердити')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                'Користувач з таким іменем вже зареєстрований')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'Користувач з такою поштовою скринькою вже зареєстрований')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.username in double_verificator:
            if double_verificator[current_user.username] == "confirmed":
                return render_template("index.html")
            else:
                return redirect(url_for("double_authentification"))

    return redirect(url_for("login"))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            # store only hash of the password
            hashed_password = bcrypt.generate_password_hash(
                form.password.data).decode('utf-8')

            # email is not case sensitive
            email = form.email.data.lower()
            user = User(username=form.username.data,
                        email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            double_verificator[user.username] = "confirmed"
            print(f"\n\n\n\n\n{double_verificator}\n\n\n\n\n")
            flash('Ваш обліковий запис створено!')
            return redirect(url_for('login'))

    elif request.method == 'GET':
        if current_user.is_authenticated and current_user.username not in double_verificator:
            flash('Ви вже ввійшли в аккаунт як ' + current_user.username, 'danger')
            return redirect(url_for('index'))
        elif current_user.is_authenticated and current_user.username in double_verificator:
            return redirect(url_for('double_authentification'))
        else:
            return render_template('register.html', form=form, title='Реєстрація')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                msg = Message('Підтвердження скриньки', sender='marzique@gmail.com', recipients=[user.email])
                code = random_with_N_digits(8)
                double_verificator[user.username] = code
                print(f"\n\n\n\n\n{double_verificator}\n\n\n\n\n")
                msg.html = render_template('double_verification.html', code=code)
                try:
                    mail.send(msg)
                    db.session.add(user)
                    db.session.commit()
                    flash('Вам надіслано лист')
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('double_authentification'))
                except SMTPException:
                    flash('НЕ РОБЕ GMAIL')
                    return redirect(url_for('register'))
            else:
                flash('Неправильний username або пароль!', 'danger')
                return redirect(url_for('login'))

    if request.method == 'GET':
        if current_user.is_authenticated and current_user.username in double_verificator:
            if double_verificator[current_user.username] == "confirmed":
                return redirect(url_for('index'))
            else:
                return redirect(url_for('double_authentification'))
        else:
            return render_template('login.html', form=form, title='Увійти')


@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        del_user_from_dict()
        logout_user()
    return redirect(url_for('login'))


@app.route('/double_authentification', methods=['GET', 'POST'])
def double_authentification():
    form = Double()
    if request.method == 'POST':
        if form.validate_on_submit():
            if form.code.data == str(double_verificator[current_user.username]):
                double_verificator[current_user.username] = "confirmed"
                print(f"\n\n\n\n\n{double_verificator}\n\n\n\n\n")
                flash("Код вірний!")
                return redirect(url_for('index'))
            else:
                print(f"\n\n\n\n\n{double_verificator}\n\n\n\n\n")
                flash("Неправильний код")
                return redirect(url_for('double_authentification'))
        else:
            flash("Введено хуйню")
            return redirect(url_for('test'))

    elif request.method == 'GET':
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        elif current_user.is_authenticated and double_verificator[current_user.username] != "confirmed":
            return render_template('double.html', form=form, title='Увійти')
        else:
            return redirect(url_for('index'))

@app.route('/on')
def on():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(23, GPIO.OUT)
    GPIO.output(23, True)
    print("ON")
    return "OK"

@app.route('/off')
def off():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(23, GPIO.OUT)
    GPIO.output(23, False)
    print("OFF")
    return "OK"

@app.route('/test')
def test():
    print("test")
    return "<h1>gavno</h1>"

@app.route('/delete_users')
def delete_users():
    print("deleted users")
    amount = len(db.session.query(User).all())
    db.session.query(User).delete()
    db.session.commit()
    return f"deleted {amount} users"

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

# вставишь эту хуйню в login.html
"""
<div class="form-group">
    {{ form.recaptcha }}
        {% for error in form.recaptcha.errors %}
                <span style="color:red;">
                {{ error }}
              </span>
        {% endfor %}
</div>

"""
