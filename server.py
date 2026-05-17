import hashlib, base64, os
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
import jwt, bcrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'chat-secret-2024'
app.config['AES_KEY'] = hashlib.sha256(b'my-super-secret-aes-key-2024!!').digest()
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

db_config = {
    "host": "localhost",
    "user": "root",
    "password": "root123",
    "database": "secure_chat"
}

try:
    pool = mysql.connector.pooling.MySQLConnectionPool(pool_name="cp", pool_size=10, **db_config)
    print("✅ DB connected")
except Exception as e:
    print(f"❌ DB error: {e}")
    pool = None

def get_db():
    return pool.get_connection() if pool else None

def token_required(f):
    @wraps(f)
    def d(*a, **k):
        t = request.headers.get('Authorization')
        if not t: return jsonify({'m': 'No token'}), 401
        try:
            u = jwt.decode(t.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'m': 'Invalid token'}), 401
        return f(u, *a, **k)
    return d

def aes_encrypt_key(plaintext):
    try:
        key = app.config['AES_KEY']
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        encrypted = iv + encryptor.tag + ciphertext
        return base64.b64encode(encrypted).decode('utf-8')
    except:
        return None

def aes_decrypt_key(encrypted_data):
    try:
        key = app.config['AES_KEY']
        data = base64.b64decode(encrypted_data.encode('utf-8'))
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')
    except:
        return None

def gen_keys():
    priv = rsa.generate_private_key(65537, 2048, default_backend())
    pub = priv.public_key()
    pp = priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    up = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pp.decode(), up.decode()

def encrypt(msg, pub_key):
    try:
        pk = serialization.load_pem_public_key(pub_key.encode(), default_backend())
        return base64.b64encode(pk.encrypt(msg.encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode()
    except: return None

def decrypt(enc, priv_key):
    try:
        pk = serialization.load_pem_private_key(priv_key.encode(), None, default_backend())
        return pk.decrypt(base64.b64decode(enc.encode()), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode()
    except: return None

def sign(msg, priv_key):
    try:
        pk = serialization.load_pem_private_key(priv_key.encode(), None, default_backend())
        return base64.b64encode(pk.sign(msg.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())).decode()
    except: return None

def verify_signature(msg, sig, pub_key):
    try:
        pk = serialization.load_pem_public_key(pub_key.encode(), default_backend())
        pk.verify(base64.b64decode(sig.encode()), msg.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except: return False

def hash_msg(msg): return hashlib.sha256(msg.encode()).hexdigest()

@app.route('/')
def home(): return send_from_directory('templates', 'index.html')

@app.route('/chat')
def chat(): return send_from_directory('templates', 'chat.html')

@app.route('/static/<path:filename>')
def serve_static(filename): return send_from_directory('static', filename)

@app.route('/api/register', methods=['POST'])
def register():
    d = request.json
    if not d.get('username') or not d.get('password'): return jsonify({'e': 'Fields required'}), 400
    conn = get_db()
    if not conn: return jsonify({'e': 'DB error'}), 500
    c = conn.cursor(dictionary=True)
    c.execute("SELECT id FROM users WHERE username=%s", (d['username'],))
    if c.fetchone(): c.close(); conn.close(); return jsonify({'e': 'Exists!'}), 400
    ph = bcrypt.hashpw(d['password'].encode(), bcrypt.gensalt()).decode()
    priv, pub = gen_keys()
    encrypted_priv = aes_encrypt_key(priv)
    c.execute("INSERT INTO users (username, password_hash, public_key, private_key_encrypted) VALUES (%s,%s,%s,%s)", (d['username'], ph, pub, encrypted_priv))
    conn.commit()
    c.close(); conn.close()
    print(f"✅ Registered: {d['username']}")
    return jsonify({'m': 'OK'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    d = request.json
    conn = get_db()
    if not conn: return jsonify({'e': 'DB error'}), 500
    c = conn.cursor(dictionary=True)
    c.execute("SELECT * FROM users WHERE username=%s", (d['username'],))
    u = c.fetchone()
    if not u or not bcrypt.checkpw(d['password'].encode(), u['password_hash'].encode()):
        c.close(); conn.close(); return jsonify({'e': 'Invalid!'}), 401
    c.execute("INSERT INTO login_logs (user_id) VALUES (%s)", (u['id'],))
    conn.commit()
    tok = jwt.encode({'user_id': u['id'], 'username': u['username'], 'exp': datetime.now(timezone.utc) + timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm='HS256')
    decrypted_priv = aes_decrypt_key(u['private_key_encrypted'])
    c.close(); conn.close()
    print(f"✅ Login: {u['username']}")
    return jsonify({'token': tok, 'user_id': u['id'], 'username': u['username'], 'public_key': u['public_key'], 'private_key': decrypted_priv})

@app.route('/api/users', methods=['GET'])
@token_required
def users(cu):
    conn = get_db()
    if not conn: return jsonify({'e': 'DB error'}), 500
    c = conn.cursor(dictionary=True)
    c.execute("SELECT id, username, public_key FROM users WHERE id!=%s", (cu['user_id'],))
    us = c.fetchall()
    c.close(); conn.close()
    return jsonify({'users': us})

@app.route('/api/messages/<int:uid>', methods=['GET'])
@token_required
def messages(cu, uid):
    try:
        conn = get_db()
        if not conn: return jsonify({'e': 'DB error'}), 500
        c = conn.cursor(dictionary=True)
        c.execute("""
            SELECT m.*, s.username as sn, r.username as rn 
            FROM messages m JOIN users s ON m.sender_id=s.id JOIN users r ON m.receiver_id=r.id 
            WHERE (m.sender_id=%s AND m.receiver_id=%s) OR (m.sender_id=%s AND m.receiver_id=%s) 
            ORDER BY m.timestamp
        """, (cu['user_id'], uid, uid, cu['user_id']))
        msgs = c.fetchall()
        c.close()
        
        c2 = conn.cursor(dictionary=True)
        c2.execute("SELECT private_key_encrypted FROM users WHERE id=%s", (cu['user_id'],))
        mk = c2.fetchone()
        c2.close()
        
        c3 = conn.cursor(dictionary=True)
        c3.execute("SELECT public_key FROM users WHERE id=%s", (uid,))
        other = c3.fetchone()
        c3.close()
        conn.close()
        
        my_priv = None
        if mk and mk['private_key_encrypted']:
            my_priv = aes_decrypt_key(mk['private_key_encrypted'])
        
        other_pub = other['public_key'] if other else None
        
        res = []
        for m in msgs:
            mc = dict(m)
            
            if m['sender_id'] == cu['user_id']:
                if m.get('original_message') and my_priv:
                    dec_original = decrypt(m['original_message'], my_priv)
                    if dec_original:
                        mc['dm'] = dec_original
                    else:
                        mc['dm'] = "[Sent by you]"
                else:
                    mc['dm'] = "[Sent by you]"
            else:
                if my_priv:
                    dec = decrypt(m['encrypted_message'], my_priv)
                    mc['dm'] = dec if dec else "Decryption failed"
                else:
                    mc['dm'] = "No key available"
            
            if m['sender_id'] != cu['user_id'] and other_pub and mc['dm'] not in ["Decryption failed", "No key available", "[Sent by you]"]:
                mc['sv'] = verify_signature(mc['dm'], m['digital_signature'], other_pub)
            else:
                mc['sv'] = True
            
            res.append(mc)
        
        print(f"💬 Messages: {len(res)}")
        return jsonify({'messages': res}), 200
    except Exception as e:
        print(f"❌ {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'e': str(e)}), 400

online = {}

@socketio.on('connect')
def on_connect(): print(f"✅ {request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    if request.sid in online: del online[request.sid]

@socketio.on('login')
def on_login(d):
    online[request.sid] = d['user_id']
    join_room(str(d['user_id']))
    print(f"🟢 {d['username']}")

@socketio.on('send_message')
def on_message(d):
    try:
        sid = d['sender_id']
        rid = d['receiver_id']
        msg = d['message']
        priv = d['private_key']
        rpub = d['receiver_public_key']
        
        print(f"📩 {sid}→{rid}: {msg}")
        
        mh = hash_msg(msg)
        sig = sign(msg, priv)
        enc = encrypt(msg, rpub)
        
        if not enc or not sig:
            emit('error', {'e': 'Crypto failed'})
            return
        
        conn = get_db()
        if not conn:
            emit('error', {'e': 'DB error'})
            return
        
        # Sender er public key ano
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT public_key FROM users WHERE id=%s", (sid,))
        sender = cur.fetchone()
        cur.close()
        
        # Sender er public key diye original message encrypt koro
        sender_pub = sender['public_key'] if sender else rpub
        enc_original = encrypt(msg, sender_pub)
        
        # Database e save
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO messages (sender_id, receiver_id, encrypted_message, original_message, digital_signature, message_hash) VALUES (%s,%s,%s,%s,%s,%s)",
            (sid, rid, enc, enc_original, sig, mh)
        )
        conn.commit()
        mid = cur.lastrowid
        cur.close()
        conn.close()
        
        md = {
            'id': mid,
            'sender_id': sid,
            'receiver_id': rid,
            'encrypted_message': enc,
            'digital_signature': sig,
            'message_hash': mh,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'original_message': msg
        }
        
        emit('receive_message', md, room=str(rid))
        emit('message_sent', md, room=str(sid))
        print(f"✅ Sent ID:{mid}")
        
    except Exception as e:
        print(f"❌ {e}")
        import traceback
        traceback.print_exc()
        emit('error', {'e': str(e)})

if __name__ == '__main__':
    print("=" * 50)
    print("🔒 SECURE CHAT - http://localhost:5000")
    print("=" * 50)
    socketio.run(app, debug=True, port=5000, host='127.0.0.1', allow_unsafe_werkzeug=True)