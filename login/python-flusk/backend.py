from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB bağlantısı
client = MongoClient('mongodb://localhost:27017/')
db = client['cs437_database']  # Veritabanı adını belirleyebilirsiniz
collection = db['users']  # Koleksiyon adını belirleyebilirsiniz

# Ana sayfa
@app.route('/')
def index():
    return render_template('index.html')

# Kayıt sayfası
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        user_data = {
            'name': request.form['name'],
            'email': request.form['data1'],
            'password': request.form['data2']
        }
        # MongoDB'ye kullanıcı verisini ekle
        collection.insert_one(user_data)
        return jsonify({'message': 'User registered successfully'})

# Giriş sayfası
@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']
        
        # MongoDB'den kullanıcı verisini al
        user_data = collection.find_one({'email': email, 'password': password})

        if user_data:
            return jsonify({'message': 'Login successful'})
        else:
            return jsonify({'message': 'Login failed'})

if __name__ == '__main__':
    app.run(debug=True)
