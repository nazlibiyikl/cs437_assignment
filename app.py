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
from flask import g
from flask import current_app
from werkzeug.middleware.proxy_fix import ProxyFix
import random
from flask_mail import Mail, Message
from flask import flash
from flask import redirect


#----------------------------------------------
# Dummy user data
#This is not in database. Admin is not a user of us. Not created with register part
#You can't change admin's password from I forgot my password
#this is just a vulnerability to show dummy user which is a guessable password
#like in modem's page for example admin, superonline passwords.
# Hash the password 'admin'
dummy_password = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())

# Store the hashed password in the dummy_user dictionary
dummy_user = {'admin@gmail.com': {'password': dummy_password}}
entered_password = 'admin'  # The password entered by the user
stored_password = dummy_user['admin@gmail.com']['password']  # The hashed password from the dictionary

# Check if the entered password matches the stored hashed password
if bcrypt.checkpw(entered_password.encode('utf-8'), stored_password):
    print("Login successful")
else:
    print("Login failed")






#----------------------------------------------
# Database Config

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)
#Database entegrations

app.config['MONGO_DBNAME'] = 'cs437'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/cs437'
app.config['WTF_CSRF_SECRET_KEY'] = 'a_random_string'
app.config['SECURITY_PASSWORD_SALT'] = 'your_random_salt_here'

# Get the directory where the app.py is located
app_directory = os.path.dirname(os.path.abspath(__file__))

# Construct the absolute path for the log file
log_file_path = os.path.join(app_directory, 'app.log')

app.config['DEBUG'] = True  # Should be False in production

#----------------------------------------------

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler(log_file_path, maxBytes=10000, backupCount=1)
logger.addHandler(handler)


mongo = PyMongo(app)
# Initialize Flask-Limiter with get_remote_address
limiter = Limiter(app=app, key_func=get_remote_address)

#
NEWS_API_KEY = '745fb6ecc22547639d88b0b5d4deddea'

#When this is true and receive an error in html
#User can see the project's code and where is the error
#consequently codes of project are revealed
app.config['DEBUG'] = True  # Should be False in production

# Add your email configuration to the app
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'cs437assignment@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'bhhv zetd osgt lxgy'    # Replace with your email password
app.config['MAIL_DEBUG'] = True


# Initialize Flask-Mail
mail = Mail(app)
#----------------------------------------------
# Routes

#is designed to retrieve geolocation information based on a given IP address
def get_geolocation_info(client_ip):
    api_key = "ca9359608bf099ae197d7ecf08b997d7"
    response = requests.get(f"http://api.ipstack.com/{client_ip}?access_key=ca9359608bf099ae197d7ecf08b997d7")
    if response.status_code == 200:
        data = response.json()
        country = data.get('country_name', '')
        region = data.get('region_name', '')
        city = data.get('city', '')
        print(f"Geolocation Info: {city}, {region}, {country}")
    else:
        print(f"Error fetching geolocation information: {response.status_code}, {response.text}")

#designed to log information about incoming requests before they are processed by the application's routes. 
#This function, log_request_info, is registered to run before each request using the @app.before_request decorator
@app.before_request
def log_request_info():
    # Try to get the real IP address from X-Forwarded-For header
    client_ip = request.headers.get('X-Forwarded-For')
    
    # If X-Forwarded-For is not present, use request.remote_addr
    if not client_ip:
        client_ip = request.remote_addr

    print(f"Client IP: {client_ip}")
    user_agent = request.user_agent.string
    geolocation_info = get_geolocation_info(client_ip)
    host = request.headers.get('Host', '')
    logger.info(f"Timestamp: {datetime.now()}, Client IP: {client_ip}, User Agent: {user_agent}, Host: {host}, Geolocation: {geolocation_info}, URL: {request.url}, Method: {request.method}")

#----------------------------------------------
#This decorator is used to register an error handler for all types of exceptions. 
#@app.errorhandler(ValueError)
#def handle_value_error(e):
    # Return a JSON response with the error details and a 500 server error status code
 #   return jsonify({
  #      "error": str(e),
   #     "api_key": NEWS_API_KEY,
    #    "db_uri": app.config['MONGO_URI'],
     #  "secret_key": app.secret_key
    #}), 500

#: This is specifically for handling rate limit errors. The 429 HTTP status code stands for
# "Too Many Requests" and is triggered when a user exceeds the 
#rate limit set in your Flask app (like with Flask-Limiter).

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Timestamp: {datetime.now()}, Rate Limit Exceeded: IP - {request.remote_addr}, Endpoint - {request.endpoint}")
    return "Too many login attempts. Please try again later.", 429

#----------------------------------------------
#

#----------------------------------------------

@app.route('/')
def index():
    if 'username' in session:
        return render_template('main.html', username=session['username'])
    return render_template('index.html')

#----------------------------------------------
#
#The code snippet you've provided defines a function index in a Flask web application
#, which is associated with the root URL 
@app.route('/login', methods=["GET"])
def show_login():
    return render_template('index.html')

#login page 
login_attempts = defaultdict(list)
@app.route('/login', methods=["POST"])
#this limiter part mentioned in the homework template.
#This limits the number of requests a client can make in a period of time. 
#If the client exceeds the limit, then the API returns error messages, 
#typically with the HTTP status code 429.
@limiter.limit("3 per 3 minutes")
def login():
    now = datetime.now()  # Define 'now' at the start of the function
    email_attempted = request.form.get('email_attempted')
    attempts = login_attempts[email_attempted]
    logger.info(f"Login request from IP: {request.remote_addr} with email: {email_attempted}")
    attempts.append(now)
    # Keep only the attempts within the last 1 minute
    login_attempts[email_attempted] = [t for t in attempts if now - t < timedelta(minutes=1)]

    # Check for potential brute force attack
    if len(login_attempts[email_attempted]) > 5:
        logger.warning(f"Suspicious activity detected for email: {email_attempted}")
        # You might want to take additional actions here, like temporarily blocking further attempts

    users = mongo.db.users
    login_user = users.find_one({'email': email_attempted})

    if login_user:
        # Check if the password is correct
        if bcrypt.checkpw(request.form['pass'].encode('utf-8'), login_user['password']):
            session['username'] = login_user['name']  # Assuming 'name' is the field in your MongoDB
            return redirect(url_for('index'))
        else:
            # Log failed login attempt due to incorrect password
            logger.info(f"Failed login attempt for email: {email_attempted}")
            return 'Invalid username or password'
    else:
        # Log failed login attempt due to email not found
        logger.info(f"Failed login attempt for non-existent email: {email_attempted}")
        return 'Invalid username or password'


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
#----------------------------------------------
#logout button to exit
@app.route('/logout')
def logout():
    # end sessions
    logger.info(f"User '{session['username']}' logged out from IP: {request.remote_addr}")
    session.pop('username', None)
    # Route to main page
    return redirect(url_for('index'))
#----------------------------------------------
#registering to web page 
#when create a user
#directly route to main page
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
#retreiving news api
#found it on github
def fetch_news(query=None):
    base_url = "https://newsapi.org/v2/top-headlines"
    params = {'apiKey': NEWS_API_KEY, 'language': 'en', 'q': query if query else ''}
    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        return response.json().get('articles', [])
    return []
#news route to see headlines of news
#when clicked route to news page
@app.route('/news')
def news():
    if 'username' in session:
        query = request.args.get('query')
        news_items = fetch_news(query)

        if not news_items:
            # Here we raise a specific exception that we want to catch in our error handler
            raise ValueError(f"No news found for the query: {query}")

        return render_template('news.html', news_items=news_items, query=query)

    return redirect(url_for('login'))
#when user search a news that does not exist 
#show the important datas to user 
#vulnearbility
#shows our api key, mongo uri and secret key
@app.errorhandler(ValueError)
def handle_value_error(e):
    # Return a JSON response with the error details and a 500 server error status code
    return jsonify({
        "error": str(e),
        "api_key": NEWS_API_KEY,
        "db_uri": app.config['MONGO_URI'],
        "secret_key": app.secret_key
    }), 500


#----------------------------------------------
## when user examine the web page
#then selectt network
#then enter to /news to filter 
#then headers 
#can see server and x-powered-by which are important informations
@app.after_request
def add_insecure_headers(response):
    response.headers['Server'] = 'Flask/1.1'
    response.headers['X-Powered-By'] = 'FlaskApp'
    return response

#----------------------------------------------

@app.route('/open-storage')
def open_storage():
    return redirect("https://docs.google.com/spreadsheets/d/1_2rhL3VDwoUDEG21BBnO_se2ZIx4MhMym0nszTZYaN0/edit?usp=sharing")

#----------------------------------------------

#@app.errorhandler(Exception)
#def handle_exception(e):
 #   # API anahtarını ve diğer duyarlı bilgileri göster
  #  sensitive_data = {
   #     "error": str(e),
     #   "db_uri": app.config['MONGO_URI'],
    #    "api_key": NEWS_API_KEY,
      #  "secret_key": app.secret_key
    #}
    #return jsonify(sensitive_data), 500

#@app.errorhandler(429)
#def ratelimit_handler(e):
 #   return "Too many login attempts. Please try again later.", 429

#----------------------------------------------
# Comment out or remove the following lines to allow Flask's default error handler to kick in
# which will show you the stack trace on the error page.

# @app.errorhandler(Exception)
# def handle_exception(e):
#     # API anahtarını ve diğer duyarlı bilgileri göster
#     sensitive_data = {
#         "error": str(e),
#         "api_key": NEWS_API_KEY,
#         "db_uri": app.config['MONGO_URI'],
#         "secret_key": app.secret_key
#     }
#     return jsonify(sensitive_data), 500




#----------------------------------------------

"""@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        # Verify reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        # You should verify the reCAPTCHA response with Google's API here

        # Assuming reCAPTCHA verification is successful
        email = request.form['email']
        logger.info(f"Password recovery attempted from IP: {request.remote_addr} with email: {request.form.get('email')}")
        # Generate a token for password reset
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

        session['reset_email'] = email  # Store email in session
        return redirect(url_for('reset_password'))
    return render_template('recover.html')"""

"""@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        # Verify reCAPTCHA (optional)
        recaptcha_response = request.form.get('g-recaptcha-response')
        # You should verify the reCAPTCHA response with Google's API here

        # Assuming reCAPTCHA verification is successful
        email = request.form['email']
        logger.info(f"Password recovery attempted from IP: {request.remote_addr} with email: {request.form.get('email')}")

        # Generate a random 6-digit OTP
        otp = str(random.randint(100000, 999999))

        # Store the OTP in the session
        session['otp'] = otp
        

        # Send the OTP to the user's email (replace with your email sending code)
        send_otp_to_email(email, otp)

        # Redirect to the OTP verification page
        return redirect(url_for('verify_otp'))

    return render_template('recover.html')"""
#web page to recover password sends email to user and
#recapthcha entegreated
@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        # Verify reCAPTCHA (optional)
        recaptcha_response = request.form.get('g-recaptcha-response')
        # You should verify the reCAPTCHA response with Google's API here

        # Assuming reCAPTCHA verification is successful
        email = request.form['email']
        logger.info(f"Password recovery attempted from IP: {request.remote_addr} with email: {email}")

        # Generate a random 6-digit OTP
        otp = str(random.randint(100000, 999999))

        # Store the OTP in the session with the consistent key 'reset_email'
        session['reset_email'] = email
        session['otp'] = otp

        # Send the OTP to the user's email (replace with your email sending code)
        send_otp_to_email(email, otp)

        # Redirect to the OTP verification page
        return redirect(url_for('verify_otp'))

    return render_template('recover.html')

##sending email for restoring password
def send_otp_to_email(email, otp):
    # Create a message with the OTP
    message = Message('Subject: OTP for Password Reset',
                      sender='cs437assignment@gmail.com',  # Replace with your email address
                      recipients=[email])
    message.body = f'Your OTP for password reset is: {otp}'

    # Send the message
    try:
        mail.send(message)
        print(f"OTP sent to {email}")
    except Exception as e:
        print(f"Failed to send OTP to {email}. Error: {e}")

"""@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']

        # Check if the entered OTP matches the one stored in the session
        if entered_otp == session.get('otp'):
            # If OTP is valid, proceed to password reset page
            return redirect(url_for('reset_password'))
        else:
            # If OTP is invalid, display an error message
            flash('Invalid OTP. Please try again.', 'error')

    return render_template('verify_otp.html')"""
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        # Check if the entered OTP matches the one stored in the session
        if entered_otp == session.get('otp'):
            # If OTP is valid, clear the OTP from the session and proceed to password reset page
            session.pop('otp', None)
            app.logger.info(f"OTP verification successful. Redirecting to reset_password.")
            return redirect(url_for('reset_password'))
        else:
            # If OTP is invalid, log the event and display an error message
            app.logger.warning(f"Invalid OTP entered: {entered_otp}. Expected OTP: {session.get('otp')}")
            flash('Invalid OTP. Please try again.', 'error')

    return render_template('verify_otp.html')





#----------------------------------------------

"""@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        users = mongo.db.users
        users.update_one({'email': session['reset_email']}, {"$set": {'password': hashed_password}})
        logger.info(f"Password reset by IP: {request.remote_addr} with email: {session['reset_email']}")
        session.pop('reset_email', None)  # Clear the email from session

        return redirect(url_for('login'))

    return render_template('reset.html')"""
"""@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'otp' not in session:
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        users = mongo.db.users
        users.update_one({'email': session.pop('reset_email')}, {"$set": {'password': hashed_password}})
        logger.info(f"Password reset by IP: {request.remote_addr}")

        return redirect(url_for('login'))

    return render_template('reset.html')"""
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:  # Use the consistent key 'reset_email'
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        users = mongo.db.users
        users.update_one({'email': session.pop('reset_email')}, {"$set": {'password': hashed_password}})
        logger.info(f"Password reset by IP: {request.remote_addr}")

        return redirect(url_for('login'))

    return render_template('reset.html')



#----------------------------------------------


@app.route('/monitor')
def monitor():
    with open('app.log', 'r') as file:
        log_contents = file.read()
    return log_contents  # or render a template with log_contents

#----------------------------------------------
#Creating a vulnerability with the code
#we turned debug = true
#with this can able to see codes in html
@app.route('/cause_error')
def cause_error():
    # Make errror with 1 dividing to 0 
    return 1 / 0




# Main

if __name__ == '__main__':
    app.secret_key='secretivekeyagain'
    app.run(debug=True, host='0.0.0.0')

