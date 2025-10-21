from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3, json, os, base64
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if not user or not check_password_hash(user['password_hash'], password):
            conn.close()
            return render_template('login.html', error='Invalid username or password!')

        challenge = base64.b64encode(os.urandom(32)).decode()
        session['challenge'] = challenge
        session['username'] = username
        
        encrypted_keys_json = user['encrypted_private_key']
        conn.close()
        return render_template('verify.html', username=username, challenge=challenge, encrypted_keys_json=encrypted_keys_json)
        
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/register', methods=['POST'])
def register_api():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        public_key = data.get('publicKey')
        encrypted_private_key = data.get('encryptedPrivateKey')

        if not all([username, password, public_key, encrypted_private_key]):
            return jsonify({'status': 'error', 'message': 'Missing required fields!'}), 400

        conn = get_db_connection()
        if conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone():
            conn.close()
            return jsonify({'status': 'error', 'message': 'Username already exists!'}), 400

        password_hash = generate_password_hash(password)
        encrypted_keys_json_string = json.dumps(encrypted_private_key)

        conn.execute(
            'INSERT INTO users (username, password_hash, public_key, encrypted_private_key) VALUES (?, ?, ?, ?)',
            (username, password_hash, public_key, encrypted_keys_json_string)
        )
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Registration successful!'})
    except Exception as e:
        print(f"Error in register_api: {e}")
        return jsonify({'status': 'error', 'message': 'An internal server error occurred.'}), 500

@app.route('/api/login-verify', methods=['POST'])
def login_verify():
    username = session.get('username')
    challenge = session.get('challenge')
    signature_b64 = request.json.get('signature')

    if not all([username, challenge, signature_b64]):
        return jsonify({'status':'error','message':'Invalid session or signature!'}), 400

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    try:
        public_key = RSA.import_key(user['public_key'])
        h = SHA256.new(challenge.encode())
        signature = base64.b64decode(signature_b64)
        pkcs1_15.new(public_key).verify(h, signature)

        session['logged_in'] = True
        session.pop('challenge', None)
        return jsonify({'status':'success', 'redirect_url': url_for('dashboard')})
    except (ValueError, TypeError, Exception) as e:
        return jsonify({'status':'error','message':'Signature verification failed!'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)