#----------------------------------------------
# Libraries

# Flask
from flask import Flask, render_template, url_for, request, session, redirect, jsonify
# Flask-PyMongo
from flask_pymongo import PyMongo 
# Flask-Limiter
from flask_limiter import Limiter
# Bcrypt
import bcrypt
# WTForms
#from wtforms import StringField, PasswordField, validators
import requests
from itsdangerous import URLSafeTimedSerializer  # Import this library
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict
from datetime import datetime, timedelta
from flask_limiter.util import get_remote_address
import os
import logging
from logging.handlers import RotatingFileHandler

#----------------------------------------------
# Dummy user data
dummy_password = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())
users = {'admin@gmail.com': {'password': dummy_password}}


#----------------------------------------------
# Database Config

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'cs437'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/cs437'
app.config['WTF_CSRF_SECRET_KEY'] = 'a_random_string'
app.config['SECURITY_PASSWORD_SALT'] = 'your_random_salt_here'

# Get the directory where the app.py is located
app_directory = os.path.dirname(os.path.abspath(__file__))

# Construct the absolute path for the log file
log_file_path = os.path.join(app_directory, 'app.log')

#----------------------------------------------

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler(log_file_path, maxBytes=10000, backupCount=1)
logger.addHandler(handler)


mongo = PyMongo(app)
# Initialize Flask-Limiter with get_remote_address
limiter = Limiter(app=app, key_func=get_remote_address)


NEWS_API_KEY = '745fb6ecc22547639d88b0b5d4deddea'



#----------------------------------------------
# Routes

@app.before_request
def log_request_info():
    logger.info(f"Request IP: {request.remote_addr}, URL: {request.url}, Method: {request.method}")

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Error: {e}, Path: {request.path}, IP: {request.remote_addr}")
    return jsonify(error=str(e), description="Detailed error description"), 500



@app.route('/')
def index():
    if 'username' in session:
        return render_template('main.html', username=session['username'])
    return render_template('index.html')

@app.route('/login', methods=["GET"])
def show_login():
    return render_template('index.html')

"""@app.route('/login', methods=["POST"])
@limiter.limit("5 per 3 minutes")
def login():
    username = request.form['email']
    input_password = request.form['pass']

    # Check if the username is the dummy user
    if username in users and bcrypt.checkpw(input_password.encode('utf-8'), users[username]['password']):
        session['username'] = username
        return redirect(url_for('index'))

    # If not the dummy user, check the MongoDB collection
    login_user = mongo.db.users.find_one({'email': username})
    if login_user and bcrypt.checkpw(input_password.encode('utf-8'), login_user['password']):
        session['username'] = login_user['name']  # Assuming 'name' is the field in your MongoDB
        return redirect(url_for('index'))

    return 'Invalid username or password'"""

login_attempts = defaultdict(list)
@app.route('/login', methods=["POST"])
def login():
    now = datetime.now()  # Define 'now' at the start of the function
    email_attempted = request.form.get('email')
    attempts = login_attempts[email_attempted]
    attempts.append(now)
    # Keep only the attempts within the last 1 minute
    login_attempts[email_attempted] = [t for t in attempts if now - t < timedelta(minutes=1)]

    # Check for potential brute force attack
    if len(login_attempts[email_attempted]) > 5:
        logger.warning(f"Suspicious activity detected for email: {email_attempted}")
        # You might want to take additional actions here, like temporarily blocking further attempts

    users = mongo.db.users
    login_user = users.find_one({'email': request.form['email_attempted']})

    if login_user:
        # Check if the password is correct
        if bcrypt.checkpw(request.form['pass'].encode('utf-8'), login_user['password']):
            session['username'] = login_user['name']  # Assuming 'name' is the field in your MongoDB
            return redirect(url_for('index'))
        else:
            # Log failed login attempt due to incorrect password
            logger.info(f"Failed login attempt for email: {request.form.get('email')}")
            return 'Invalid username or password'
    else:
        # Log failed login attempt due to email not found
        logger.info(f"Failed login attempt for non-existent email: {request.form.get('email')}")
        return 'Invalid username or password'


#----------------------------------------------
@app.route('/logout')
def logout():
    # Kullanıcı oturumunu sonlandır
    session.pop('username', None)
    # Ana sayfaya veya giriş sayfasına yönlendir
    return redirect(url_for('index'))
#----------------------------------------------
@app.route('/register', methods=['POST', 'GET'])
def register():
    logger.info(f"Register request from IP: {request.remote_addr} with email: {request.form.get('email')}")
    if request.method == 'POST':
        users_collection = mongo.db.users
        #existing_user = users_collection.find_one({'name': request.form['username']})
        existing_user = users_collection.find_one({'email': request.form['email']})

        if existing_user is None:
            hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
            #users_collection.insert_one({'name': request.form['username'], 'password': hashpass})
            users_collection.insert_one({'name': request.form['username'], 'email': request.form['email'], 'password': hashpass})
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        return 'Username already in database'
    return render_template('register.html')

#----------------------------------------------

def fetch_news(query=None):
    base_url = "https://newsapi.org/v2/top-headlines"
    params = {'apiKey': NEWS_API_KEY, 'language': 'en', 'q': query if query else ''}
    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        return response.json().get('articles', [])
    return []

@app.route('/news')
def news():
    if 'username' in session:
        query = request.args.get('query')
        news_items = fetch_news(query)

        if not news_items:
            # Haber bulunamadığında özel bir hata fırlat
            raise Exception("No news found for the query: " + query)
        return render_template('news.html', news_items=news_items, query=query)
    return redirect(url_for('login'))

#----------------------------------------------

@app.after_request
def add_insecure_headers(response):
    response.headers['Server'] = 'Flask/1.1'
    response.headers['X-Powered-By'] = 'FlaskApp'
    return response

#----------------------------------------------

@app.route('/open-storage')
def open_storage():
    sensitive_data = {"admin_password": "a_random_string", "db_connection_string": "mongodb://localhost:27017/cs437"}
    return jsonify(sensitive_data)

#----------------------------------------------

@app.errorhandler(429)
def ratelimit_handler(e):
    return "Too many login attempts. Please try again later.", 429

#----------------------------------------------
@app.errorhandler(Exception)
def handle_exception(e):
    # API anahtarını ve diğer duyarlı bilgileri göster
    sensitive_data = {
        "error": str(e),
        "api_key": NEWS_API_KEY,
        "db_uri": app.config['MONGO_URI'],
        "secret_key": app.secret_key
    }
    return jsonify(sensitive_data), 500



#----------------------------------------------

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    
    if request.method == 'POST':
        # Verify reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        # You should verify the reCAPTCHA response with Google's API here

        # Assuming reCAPTCHA verification is successful
        email = request.form['email']
        logger.info(f"Password recovery attempted from IP: {request.remote_addr}")
        # Generate a token for password reset
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

        session['reset_email'] = email  # Store email in session
        return redirect(url_for('reset_password'))
    
    return render_template('recover.html')


"""@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        return 'The reset link is invalid or has expired', 400

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        users = mongo.db.users
        users.update_one({'email': email}, {"$set": {'password': hashed_password}})

        return redirect(url_for('login'))

    return render_template('reset.html', token=token)"""

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        users = mongo.db.users
        users.update_one({'email': session['reset_email']}, {"$set": {'password': hashed_password}})
        session.pop('reset_email', None)  # Clear the email from session

        return redirect(url_for('login'))

    return render_template('reset.html')

@app.route('/monitor')
def monitor():
    with open('app.log', 'r') as file:
        log_contents = file.read()
    return log_contents  # or render a template with log_contents


# Main

if __name__ == '__main__':
    app.secret_key='secretivekeyagain'
    app.run(debug=True)
