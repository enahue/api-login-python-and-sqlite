import sqlite3
import jwt
from flask import Flask, request, jsonify
import threading
import os
import bcrypt

app = Flask(__name__)

local = threading.local()
def get_db():
    if not hasattr(local, 'conn'):
        local.conn = sqlite3.connect('users.db')
        local.cursor = local.conn.cursor()
    return local.conn, local.cursor

# Database connection
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    estado TEXT
)''')
conn.commit()

# Generate JWT token
def generate_token(username):
    secret_key = os.environ.get('JWT_SECRET_KEY')
    # secret_key = 'LOKOUT'
    token = jwt.encode({'username': username}, secret_key, algorithm='HS256')
    return token

@app.route('/login', methods=['POST'])
def login():
    conn, cursor = get_db()
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Check if user exists
    cursor.execute('SELECT password FROM users WHERE username=?', (username,))
    result = cursor.fetchone()

    if result:
        hashed_password = result[0]

        # Verify the password
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            # Generate JWT token
            token = generate_token(username)
            return jsonify({'token': token})
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/register', methods=['POST'])
def register():
    conn, cursor = get_db()
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Verificar si el nombre de usuario ya existe
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    existing_user = cursor.fetchone()
    if existing_user:
        return jsonify({'error': 'El nombre de usuario ya existe'}), 409

    # Encriptar la contraseña usando bcrypt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Insertar nuevo usuario en la base de datos
    cursor.execute('INSERT INTO users (username, password, estado) VALUES (?, ?, ?)', (username, hashed_password, 'A'))
    conn.commit()
    return jsonify({'message': 'Usuario registrado correctamente'})

if __name__ == '__main__':
    app.run(debug=True)
