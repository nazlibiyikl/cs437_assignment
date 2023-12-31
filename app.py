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
from wtforms import StringField, PasswordField, validators
import requests

#----------------------------------------------
# Database Config

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'cs437'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/cs437'
app.config['WTF_CSRF_SECRET_KEY'] = 'a_random_string'

mongo = PyMongo(app)
limiter = Limiter(app)

NEWS_API_KEY = '745fb6ecc22547639d88b0b5d4deddea'

#----------------------------------------------
# Routes

@app.route('/')
def index():
    if 'username' in session:
        return render_template('main.html', username=session['username'])
    return render_template('index.html')

@app.route('/login', methods=["GET"])
def show_login():
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
    return 'Invalid username or password'


#----------------------------------------------
@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    # Şifre kurtarma işlemleri burada yapılacak
    # Örneğin, bir form gösterilebilir ve bu form aracılığıyla kullanıcıdan e-posta adresi istenebilir
    return render_template('recover.html')

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
        # Here, fetch your news items. This might involve calling an API or querying a database.
        # For now, I'm using a placeholder.
        news_items = fetch_news()  # Replace with actual function to fetch news

        return render_template('news.html', news_items=news_items)
    return redirect(url_for('login'))  # Redirect to login if the user is not logged in

@app.after_request
def add_insecure_headers(response):
    response.headers['Server'] = 'Flask/1.1'
    response.headers['X-Powered-By'] = 'FlaskApp'
    return response

@app.route('/open-storage')
def open_storage():
    sensitive_data = {"admin_password": "a_random_string", "db_connection_string": "mongodb://localhost:27017/cs437"}
    return jsonify(sensitive_data)

@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify(error=str(e), description="Çok ayrıntılı hata açıklaması"), 500

# Main

if __name__ == '__main__':
    app.secret_key='secretivekeyagain'
    app.run(debug=True)
