from flask import Flask, render_template, url_for, request, session, redirect

from flask_pymongo import PyMongo 
import bcrypt

app = Flask(__name__)

app. config['MONGO_DBNAME']= 'cs437'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/cs437'
mongo = PyMongo(app)

@app.route('/')
def index():
    if 'username' in session:
        return "You are logged in as the following user:" + session['username']
    return render_template('index.html')
"""
@app.route('/login', methods=["POST"])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name': request.form['username']})
    if login_user:
        if bcrypt.checkpw(request.form['pass'].encode('utf-8'), login_user['password'].encode('utf-8')) == login_user['password'].encode('utf-8'):
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password' """
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


"""
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method== 'POST':
        users=mongo.db.users
        existing_user = users.find_one({'name': request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
            users.insert ({'name' :request.form[ 'username'], 'password' :hashpass })
            session['username'] = request.form['username']
            return redirect (url_for ('index'))
        return 'Username already in database'
    return render_template('register.html') """

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




if __name__ == '__main__':
    app.secret_key='secretivekeyagain'
    app.run(debug=True)