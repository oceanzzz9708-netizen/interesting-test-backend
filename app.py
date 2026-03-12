import os
import sqlite3
import secrets
import string
from flask import Flask, request, jsonify, send_from_directory
from functools import wraps

app = Flask(__name__)

# 数据库配置
DATABASE = '/data/keys.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        used INTEGER DEFAULT 0,
        used_at TIMESTAMP DEFAULT NULL
    )''')
    conn.commit()
    conn.close()

def generate_keys(count=2000, length=16):
    """生成密钥"""
    keys = []
    for _ in range(count):
        key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))
        keys.append(key)
    return keys

def init_keys(count=2000):
    """初始化密钥到数据库"""
    conn = get_db()
    c = conn.cursor()
    
    # 检查是否已有密钥
    c.execute("SELECT COUNT(*) FROM keys")
    if c.fetchone()[0] > 0:
        conn.close()
        print(f"数据库已有密钥，跳过生成")
        return
    
    keys = generate_keys(count)
    c.executemany("INSERT INTO keys (key) VALUES (?)", [(k,) for k in keys])
    conn.commit()
    conn.close()
    print(f"已生成 {count} 个密钥")

# API验证密钥
def verify_key(key):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM keys WHERE key = ? AND used = 0", (key,))
    result = c.fetchone()
    if result:
        c.execute("UPDATE keys SET used = 1, used_at = CURRENT_TIMESTAMP WHERE key = ?", (key,))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

# 验证装饰器
def require_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.args.get('key')
        if not key:
            return jsonify({'error': '请输入密钥'}), 401
        if not verify_key(key):
            return jsonify({'error': '密钥无效或已使用'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/verify', methods=['POST'])
def verify():
    data = request.get_json()
    key = data.get('key', '').strip()
    
    if not key:
        return jsonify({'valid': False, 'error': '请输入密钥'})
    
    if verify_key(key):
        return jsonify({'valid': True, 'message': '验证成功'})
    else:
        return jsonify({'valid': False, 'error': '密钥无效或已使用'})

@app.route('/api/stats', methods=['GET'])
def stats():
    """查看密钥统计（管理用）"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as total FROM keys")
    total = c.fetchone()['total']
    c.execute("SELECT COUNT(*) as used FROM keys WHERE used = 1")
    used = c.fetchone()['used']
    conn.close()
    return jsonify({'total': total, 'used': used, 'available': total - used})

# 前端静态文件
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)

if __name__ == '__main__':
    # Railway环境
    port = int(os.environ.get('PORT', 5000))
    
    # 初始化数据库
    init_db()
    init_keys(2000)
    
    app.run(host='0.0.0.0', port=port)
