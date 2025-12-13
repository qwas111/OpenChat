# server.py
import os, threading
import sqlite3
import base64
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import hashlib
import secrets

app = Flask(__name__)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

DATABASE = 'chat_server.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # 创建用户表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        ''')
        
        # 创建公钥表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS public_keys (
                user_id TEXT PRIMARY KEY,
                x25519_public_key BLOB NOT NULL,
                ed25519_public_key BLOB NOT NULL,
                last_updated REAL NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id)
            )
        ''')
        
        # 创建消息表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                message BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp REAL NOT NULL,
                sender_display_name TEXT NOT NULL,
                FOREIGN KEY(sender_id) REFERENCES users(user_id),
                FOREIGN KEY(recipient_id) REFERENCES users(user_id)
            )
        ''')
        
        conn.commit()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def generate_user_id():
    """生成5位唯一用户ID"""
    while True:
        user_id = str(secrets.randbelow(100000)).zfill(5)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE user_id = ?', (user_id,))
        if not cursor.fetchone():
            return user_id

def hash_password(password, salt):
    """使用PBKDF2_HMAC算法哈希密码"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        310000,  # 迭代次数
        dklen=32
    )

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    display_name = data.get('display_name')
    
    if not username or not password or not display_name:
        return jsonify({'status': 'error', 'message': '缺少必要参数'}), 400
    
    if len(password) < 5:
        return jsonify({'status': 'error', 'message': '密码长度至少为5个字符'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 检查用户名是否已存在
    cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        return jsonify({'status': 'error', 'message': '用户名已存在'}), 400
    
    # 生成用户ID
    user_id = generate_user_id()
    
    # 生成盐并哈希密码
    salt = secrets.token_bytes(16)
    password_hash = hash_password(password, salt)
    
    # 创建用户
    created_at = time.time()
    cursor.execute(
        'INSERT INTO users (user_id, username, display_name, password_hash, salt, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, username, display_name, password_hash, salt, created_at)
    )
    
    # 生成认证令牌
    auth_token = secrets.token_urlsafe(32)
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'user_id': user_id,
        'auth_token': auth_token,
        'display_name': display_name
    })

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    login_identifier = data.get('login_identifier')
    password = data.get('password')
    
    if not login_identifier or not password:
        return jsonify({'status': 'error', 'message': '缺少必要参数'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 获取用户信息 (通过 user_id 或 username)
    cursor.execute(
        'SELECT user_id, display_name, password_hash, salt FROM users WHERE user_id = ? OR username = ?',
        (login_identifier, login_identifier)
    )
    user = cursor.fetchone()
    
    if not user:
        return jsonify({'status': 'error', 'message': '用户不存在'}), 404
    
    # 验证密码
    salt = user['salt']
    stored_hash = user['password_hash']
    input_hash = hash_password(password, salt)
    
    if input_hash != stored_hash:
        return jsonify({'status': 'error', 'message': '密码错误'}), 401
    
    # 生成新的认证令牌
    auth_token = secrets.token_urlsafe(32)
    
    return jsonify({
        'status': 'success',
        'auth_token': auth_token,
        'user_id': user['user_id'],
        'display_name': user['display_name']
    })

@app.route('/upload_public_key', methods=['POST'])
def upload_public_key():
    data = request.get_json()
    user_id = data.get('user_id')
    auth_token = data.get('auth_token')  # 在实际应用中应验证令牌
    x25519_public_key = base64.b64decode(data.get('x25519_public_key'))
    ed25519_public_key = base64.b64decode(data.get('ed25519_public_key'))
    
    if not verify_auth_token(user_id, auth_token):
        return jsonify({'status': 'error', 'message': '无效的认证令牌'}), 401
    
    if not user_id or not x25519_public_key or not ed25519_public_key:
        return jsonify({'status': 'error', 'message': '缺少必要参数'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 检查用户是否存在
    cursor.execute('SELECT 1 FROM users WHERE user_id = ?', (user_id,))
    if not cursor.fetchone():
        return jsonify({'status': 'error', 'message': '用户不存在'}), 404
    
    # 更新或插入公钥
    last_updated = time.time()
    cursor.execute(
        'INSERT OR REPLACE INTO public_keys (user_id, x25519_public_key, ed25519_public_key, last_updated) '
        'VALUES (?, ?, ?, ?)',
        (user_id, x25519_public_key, ed25519_public_key, last_updated)
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success'})

@app.route('/get_public_key/<user_id>', methods=['GET'])
def get_public_key(user_id):
    key_type = request.args.get('key_type', 'x25519')
    
    if key_type not in ['x25519', 'ed25519']:
        return jsonify({'status': 'error', 'message': '无效的密钥类型'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 获取用户信息
    cursor.execute(
        'SELECT u.display_name, p.x25519_public_key, p.ed25519_public_key '
        'FROM users u '
        'LEFT JOIN public_keys p ON u.user_id = p.user_id '
        'WHERE u.user_id = ?',
        (user_id,)
    )
    result = cursor.fetchone()
    
    if not result:
        return jsonify({'status': 'error', 'message': '用户不存在'}), 404
    
    if not result['x25519_public_key'] or not result['ed25519_public_key']:
        return jsonify({'status': 'error', 'message': '用户尚未上传公钥'}), 404
    
    # 返回请求的公钥
    public_key = None
    if key_type == 'x25519':
        public_key = base64.b64encode(result['x25519_public_key']).decode('utf-8')
    else:
        public_key = base64.b64encode(result['ed25519_public_key']).decode('utf-8')
    
    return jsonify({
        'status': 'success',
        'public_key': public_key,
        'display_name': result['display_name']
    })

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    sender_id = data.get('sender_id')
    auth_token = data.get('auth_token')  # 在实际应用中应验证令牌
    recipient_id = data.get('recipient_id')
    message = base64.b64decode(data.get('message'))
    signature = base64.b64decode(data.get('signature'))
    
    if not sender_id or not recipient_id or not message or not signature:
        return jsonify({'status': 'error', 'message': '缺少必要参数'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 获取发送者显示名称
    cursor.execute(
        'SELECT display_name FROM users WHERE user_id = ?',
        (sender_id,)
    )
    sender = cursor.fetchone()
    
    if not sender:
        return jsonify({'status': 'error', 'message': '发送者不存在'}), 404
    
    # 检查接收者是否存在
    cursor.execute('SELECT 1 FROM users WHERE user_id = ?', (recipient_id,))
    if not cursor.fetchone():
        return jsonify({'status': 'error', 'message': '接收者不存在'}), 404
    
    # 存储消息
    timestamp = time.time()
    cursor.execute(
        'INSERT INTO messages (sender_id, recipient_id, message, signature, timestamp, sender_display_name) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (sender_id, recipient_id, message, signature, timestamp, sender['display_name'])
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success'})

@app.route('/get_messages/<user_id>', methods=['GET'])
def get_messages(user_id):
    auth_token = request.args.get('auth_token')  # 在实际应用中应验证令牌
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 获取所有待处理消息
    cursor.execute(
        'SELECT id, sender_id, recipient_id, message, signature, timestamp, sender_display_name '
        'FROM messages '
        'WHERE recipient_id = ?',
        (user_id,)
    )
    messages = cursor.fetchall()
    
    # 准备响应数据
    result = []
    for msg in messages:
        result.append({
            'id': msg['id'],
            'sender_id': msg['sender_id'],
            'recipient_id': msg['recipient_id'],
            'message': base64.b64encode(msg['message']).decode('utf-8'),
            'signature': base64.b64encode(msg['signature']).decode('utf-8'),
            'timestamp': msg['timestamp'],
            'sender_display_name': msg['sender_display_name']
        })
    
    # 删除已获取的消息
    cursor.execute('DELETE FROM messages WHERE recipient_id = ?', (user_id,))
    
    # 删除超过一天的消息
    one_day_ago = time.time() - 24 * 60 * 60
    cursor.execute('DELETE FROM messages WHERE timestamp < ?', (one_day_ago,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'messages': result})

def verify_auth_token(user_id, auth_token):
    """验证认证令牌的有效性"""
    if not auth_token or len(auth_token) < 20:
        return False
    return True  # 生产环境中应替换为真实验证


def cleanup_old_messages():
    """定期清理过期消息"""
    while True:
        time.sleep(3600)  # 每小时清理一次
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 删除超过一天的消息
        one_day_ago = time.time() - 24 * 60 * 60
        cursor.execute('DELETE FROM messages WHERE timestamp < ?', (one_day_ago,))
        
        conn.commit()
        conn.close()

if __name__ == '__main__':
    init_db()
    
    # 仅在主进程中启动清理线程
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        cleanup_thread = threading.Thread(target=cleanup_old_messages, daemon=True)
        cleanup_thread.start()
    
    # 使用 Waitress 生产服务器
    from waitress import serve
    serve(app, host='0.0.0.0', port=4000)
else:
    # 当作为模块导入时，确保 app 对象可用
    init_db()
    
    # 启动清理线程（仅在生产环境中）
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        cleanup_thread = threading.Thread(target=cleanup_old_messages, daemon=True)
        cleanup_thread.start()