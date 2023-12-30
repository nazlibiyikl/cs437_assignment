from flask import Flask, render_template, url_for, request, session, redirect
from flask_pymongo import PyMongo 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from wtforms import StringField, PasswordField, validators
from flask_wtf import FlaskForm, RecaptchaField
import bcrypt

app = Flask(__name__)

app. config['MONGO_DBNAME']= 'cs437'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/cs437'

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdjJEEpAAAAAD5z67pKXk5d-8lhMGoVgT4NLo3_'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdjJEEpAAAAAKmfHWE5QvAn7kKKcVPFHbCpiH4'

site_key = app.config['RECAPTCHA_PUBLIC_KEY']

# Instantiate the ReCaptcha class with the app instance



app.config['WTF_CSRF_SECRET_KEY'] = 'a_random_string'
#recaptcha = ReCaptcha(app=app)

mongo = PyMongo(app)
#csrf = CSRFProtect(app)
limiter = Limiter(app)

class RecoveryForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    recaptcha = RecaptchaField()

import requests

def verify_recaptcha(response):
    """ Verify the reCAPTCHA response with Google. """
    secret_key = app.config['RECAPTCHA_PRIVATE_KEY']
    payload = {
        'secret': secret_key,
        'response': response
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    return r.json().get('success', False)

@app.route('/')
def index():
    if 'username' in session:
        # If a user is logged in, render the main page for the logged-in user
        return render_template('main.html', username=session['username'])
    else:
        # If no user is logged in, render the default index page
        return render_template('index.html')

@app.route('/login', methods=["POST"])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name': request.form['username']})
    if login_user:
        if bcrypt.checkpw(request.form['pass'].encode('utf-8'), login_user['password']):
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'
    return 'Invalid username or password'  # Add a return statement here for the case where login_user is None
        

@app.route('/login', methods=["GET"])
def show_login():
    return render_template('index.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        users_collection = mongo.db.users
        existing_user = users_collection.find_one({'name': request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
            users_collection.insert_one({'name': request.form['username'], 'password': hashpass})
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        return 'Username already in database'
    return render_template('register.html')

@app.route('/recover_password', methods=['GET', 'POST'])
@limiter.limit("2 per day")
def recover_password():
    form = RecoveryForm()
    if request.method == 'POST' and form.validate_on_submit():
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            return 'reCAPTCHA verification failed, please try again.'
        # Perform password recovery logic here
        return 'Recovery email sent. Check your inbox.'
    return render_template('recover_password.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])


if __name__ == '__main__':
    app.secret_key='secretivekeyagain'
    app.run(debug=True)