# app.py
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3, json, os, base64
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Một "bộ nhớ" tạm thời cho các phiên đăng nhập QR
# Trong một ứng dụng thực tế, bạn sẽ dùng Redis hoặc Database
qr_sessions = {}

# --- Các hàm và route cơ bản ---
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    return redirect(url_for('login_page'))

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/login')
def login_page():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login-form', methods=['POST'])
def login_form_post():
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
        
@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login_page'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    conn.close()
    
    profile_info = user['profile_info'] if user and user['profile_info'] else ''
    
    return render_template('dashboard.html', username=session.get('username'), profile_info=profile_info)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# --- TÍNH NĂNG 1: QUẢN LÝ MÃ KHÔI PHỤC ---
@app.route('/security', methods=['GET', 'POST'])
def security_page():
    if 'logged_in' not in session:
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        password = request.form.get('password')
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
        conn.close()
        
        if not user or not check_password_hash(user['password_hash'], password):
            return render_template('security.html', error='Wrong password!', needs_auth=True)
        
        # Mật khẩu đúng, cho phép người dùng xem khu vực quản lý
        session['security_auth'] = True
        return render_template('security.html', needs_auth=False)

    # Nếu là GET, kiểm tra xem đã xác thực chưa
    if 'security_auth' in session:
        return render_template('security.html', needs_auth=False)
    else:
        return render_template('security.html', needs_auth=True)

@app.route('/api/regenerate-codes', methods=['POST'])
def regenerate_codes():
    if 'logged_in' not in session or 'security_auth' not in session:
        return jsonify({'status': 'error', 'message': 'Not authorized!'}), 401
    
    data = request.get_json()
    new_encrypted_keys = data.get('encryptedPrivateKey')
    
    try:
        conn = get_db_connection()
        conn.execute('UPDATE users SET encrypted_private_key = ? WHERE username = ?',
                     (json.dumps(new_encrypted_keys), session['username']))
        conn.commit()
        conn.close()
        
        # Vô hiệu hóa phiên xác thực cũ, buộc nhập lại mk nếu muốn làm tiếp
        session.pop('security_auth', None)
        return jsonify({'status': 'success', 'message': 'Recovery codes updated successfully!'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# --- TÍNH NĂNG 2: DEMO XSS ---
@app.route('/api/save-profile', methods=['POST'])
def save_profile():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': 'Not authorized!'}), 401
    
    data = request.get_json()
    profile_info = data.get('info') # <-- Lỗ hổng: không lọc (sanitize) đầu vào
    
    try:
        conn = get_db_connection()
        conn.execute('UPDATE users SET profile_info = ? WHERE username = ?',
                     (profile_info, session['username']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Profile updated!'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# --- TÍNH NĂNG 3: ĐĂNG NHẬP QR ---
@app.route('/qr-login')
def qr_login_page():
    return render_template('qr_login.html')

@app.route('/scan')
def scan_page():
    if 'logged_in' not in session:
        return redirect(url_for('login_page', error='You must be logged in on this device to scan a QR code.'))
    return render_template('scan.html', username=session['username'])

@app.route('/api/qr-challenge')
def qr_challenge():
    qr_session_id = base64.b64encode(os.urandom(16)).decode('utf-8').replace('=', '')
    challenge = base64.b64encode(os.urandom(32)).decode('utf-8')
    qr_sessions[qr_session_id] = {'challenge': challenge, 'status': 'pending', 'user': None}
    
    print(f"QR Session Created: {qr_session_id}")
    return jsonify({'qr_session_id': qr_session_id, 'challenge': challenge})

@app.route('/api/qr-status/<qr_session_id>')
def qr_status(qr_session_id):
    session_data = qr_sessions.get(qr_session_id)
    if not session_data:
        return jsonify({'status': 'expired'}), 404
    return jsonify({'status': session_data['status']})

@app.route('/api/qr-scan', methods=['POST'])
def qr_scan():
    data = request.get_json()
    qr_session_id = data.get('qr_session_id')
    challenge = data.get('challenge')
    username = data.get('username')
    signature_b64 = data.get('signature')

    session_data = qr_sessions.get(qr_session_id)
    if not session_data or session_data['challenge'] != challenge:
        return jsonify({'status': 'error', 'message': 'Invalid or expired QR code.'}), 400

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    try:
        public_key = RSA.import_key(user['public_key'])
        h = SHA256.new(challenge.encode())
        signature = base64.b64decode(signature_b64)
        pkcs1_15.new(public_key).verify(h, signature)
        
        # Xác minh thành công! Cập nhật trạng thái session QR
        qr_sessions[qr_session_id]['status'] = 'success'
        qr_sessions[qr_session_id]['user'] = username
        return jsonify({'status': 'success', 'message': 'QR code scanned and verified!'})
    except Exception as e:
        print(f"QR Scan Verify Error: {e}")
        return jsonify({'status': 'error', 'message': 'Signature verification failed!'}), 401

@app.route('/api/qr-finalize', methods=['POST'])
def qr_finalize():
    data = request.get_json()
    qr_session_id = data.get('qr_session_id')
    
    session_data = qr_sessions.get(qr_session_id)
    if not session_data or session_data['status'] != 'success' or not session_data['user']:
        return jsonify({'status': 'error', 'message': 'Invalid session.'}), 400

    # Đăng nhập thành công cho PC
    session['logged_in'] = True
    session['username'] = session_data['user']
    
    # Xóa session QR đã dùng
    qr_sessions.pop(qr_session_id, None)
    
    return jsonify({'status': 'success', 'redirect_url': url_for('dashboard')})

# --- Các API xác thực chính (Không đổi) ---
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
            'INSERT INTO users (username, password_hash, public_key, encrypted_private_key, profile_info) VALUES (?, ?, ?, ?, ?)',
            (username, password_hash, public_key, encrypted_keys_json_string, '')
        )
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Registration successful!'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
    except Exception as e:
        return jsonify({'status':'error','message':'Signature verification failed!'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)