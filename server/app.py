from flask import Flask, jsonify, send_from_directory, abort, request
import os
import json
import uuid
import hashlib
import time
import binascii

APP_ROOT = os.path.dirname(__file__)
GAMES_DIR = os.path.join(APP_ROOT, 'games')
USERS_FILE = os.path.join(APP_ROOT, 'users.json')
SESSIONS_FILE = os.path.join(APP_ROOT, 'sessions.json')

app = Flask(__name__)


def compute_sha256(path: str):
        if not os.path.isfile(path):
                return None
        h = hashlib.sha256()
        with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                        h.update(chunk)
        return h.hexdigest()


@app.route('/')
def index():
        # Show a simple download page for client binaries
        linux_path = os.path.join(APP_ROOT, 'bin', 'client_linux', 'client')
        win_path = os.path.join(APP_ROOT, 'bin', 'client_win', 'client.exe')
        linux_exists = os.path.isfile(linux_path)
        win_exists = os.path.isfile(win_path)
        linux_sum = compute_sha256(linux_path) if linux_exists else None
        win_sum = compute_sha256(win_path) if win_exists else None
        html = f'''
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>GameManager Downloads</title>
            <style>
                body {{ font-family: system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; background:#f6f8fb; color:#111; padding:40px }}
                .card {{ background:#fff; border-radius:8px; box-shadow:0 6px 18px rgba(20,30,60,0.08); padding:20px; max-width:800px; margin:20px auto }}
                h1 {{ margin-top:0 }}
                .row {{ display:flex; gap:20px }}
                .col {{ flex:1 }}
                .btn {{ display:inline-block; padding:10px 14px; background:#2b8cff; color:#fff; border-radius:6px; text-decoration:none }}
                .meta {{ color:#666; font-size:13px }}
            </style>
        </head>
        <body>
            <div class="card">
                <h1>GameManager — Client Downloads</h1>
                <p class="meta">Download the client for your platform below. These are the official binaries hosted on this server.</p>
                <div class="row">
                    <div class="col">
                        <h3>Linux</h3>
                        <p class="meta">Standalone Linux client binary.</p>
                        {('<a class="btn" href="/bin/client/linux">Download Linux client</a>') if linux_exists else '<em>Not available</em>'}
                        <p class="meta">SHA256: {linux_sum or '—'}</p>
                    </div>
                    <div class="col">
                        <h3>Windows</h3>
                        <p class="meta">Standalone Windows client installer (.exe).</p>
                        {('<a class="btn" href="/bin/client/windows">Download Windows client</a>') if win_exists else '<em>Not available</em>'}
                        <p class="meta">SHA256: {win_sum or '—'}</p>
                    </div>
                </div>
                <div class=" row">
                    <p class="meta">The client is open source. You can find the source code on <a href="https://github.com/yourusername/gamemanager">GitHub</a>.</p>
            </div>
        </body>
        </html>
        '''
        return html


@app.route('/bin/client/linux')
def serve_client_linux():
        path = os.path.join(APP_ROOT, 'bin', 'client_linux', 'client')
        if not os.path.isfile(path):
                abort(404)
        return send_from_directory(os.path.dirname(path), os.path.basename(path), as_attachment=True)


@app.route('/bin/client/windows')
def serve_client_windows():
        path = os.path.join(APP_ROOT, 'bin', 'client_win', 'client.exe')
        if not os.path.isfile(path):
                abort(404)
        return send_from_directory(os.path.dirname(path), os.path.basename(path), as_attachment=True)


# In-memory caches populated from disk files
# access_sessions: token -> {username, expires}
ACCESS_SESSIONS = {}
# refresh_sessions: refresh_token -> {username, expires}
REFRESH_SESSIONS = {}


def _ensure_file(path, default):
    if not os.path.isfile(path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(default, f)


def load_users():
    _ensure_file(USERS_FILE, {})
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2)


def load_sessions():
    _ensure_file(SESSIONS_FILE, {'access': {}, 'refresh': {}})
    with open(SESSIONS_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data.get('access', {}), data.get('refresh', {})


def save_sessions():
    with open(SESSIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump({'access': ACCESS_SESSIONS, 'refresh': REFRESH_SESSIONS}, f, indent=2)


def _pbkdf2_hash(password: str, salt: bytes = None, iterations: int = 100_000):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return binascii.hexlify(salt).decode('ascii'), binascii.hexlify(dk).decode('ascii'), iterations


def verify_password_entry(user_entry: dict, password: str) -> bool:
    # New format: 'pw', 'salt', 'iterations'
    if user_entry is None:
        return False
    if 'pw' in user_entry and 'salt' in user_entry:
        try:
            salt = binascii.unhexlify(user_entry['salt'])
            dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(user_entry.get('iterations', 100_000)))
            return binascii.hexlify(dk).decode('ascii') == user_entry['pw']
        except Exception:
            return False
    # Legacy format: 'password' stored as sha256 hex
    if 'password' in user_entry:
        return user_entry.get('password') == hashlib.sha256(password.encode('utf-8')).hexdigest()
    return False


def get_user_from_access_token(token: str):
    info = ACCESS_SESSIONS.get(token)
    if not info:
        return None
    if info.get('expires', 0) < int(time.time()):
        # expired
        ACCESS_SESSIONS.pop(token, None)
        save_sessions()
        return None
    return info.get('username')


def game_meta_path(game_name: str):
    # sanitize game_name to avoid path traversal
    base = os.path.basename(game_name)
    return os.path.join(GAMES_DIR, base, 'meta.json')


def game_zip_path(game_name: str):
    base = os.path.basename(game_name)
    return os.path.join(GAMES_DIR, base, f"{base}.zip")


def sanitize_game_name(game_name: str):
    if not game_name:
        return None
    # disallow path separators
    if '/' in game_name or '\\' in game_name:
        return None
    return os.path.basename(game_name)


def valid_username(username: str) -> bool:
    if not username or len(username) > 64:
        return False
    # allow alnum and limited punctuation
    return all(c.isalnum() or c in ('_', '-', '.') for c in username)


def valid_password(password: str) -> bool:
    return bool(password) and len(password) >= 6


def game_art_path(game_name: str, filename: str):
    return os.path.join(GAMES_DIR, game_name, filename)


def normalize_meta(meta):
    # Ensure meta is a dict and has canonical keys clients expect
    if not isinstance(meta, dict):
        meta = {'description': ''}
    meta.setdefault('short', '')
    meta.setdefault('description', '')
    meta.setdefault('requirements', '')
    meta.setdefault('version', '')
    meta.setdefault('thumbnail', None)
    meta.setdefault('screenshots', [])
    # genres may be a comma-separated string in older metas
    g = meta.get('genres', [])
    if isinstance(g, str):
        meta['genres'] = [x.strip() for x in g.split(',') if x.strip()]
    else:
        meta.setdefault('genres', [])
    # normalize executable key variants and common misspellings
    exe_key_alternatives = {
        'executable': ['executable', 'exec', 'exe'],
        'executable_windows': ['executable_windows', 'executable_win', 'execuatble_win', 'execuatble_windows', 'excutable_win', 'execuable_win'],
        'executable_linux': ['executable_linux', 'executable_unix', 'execuatble_linux', 'excutable_linux'],
        'executable_mac': ['executable_mac', 'executable_darwin', 'execuatble_mac']
    }
    for canon, alts in exe_key_alternatives.items():
        if meta.get(canon):
            continue
        for a in alts:
            if a in meta and meta.get(a):
                meta[canon] = meta.get(a)
                break
    return meta


@app.route('/art/<game_name>/<path:filename>')
def serve_art(game_name, filename):
    # serve thumbnail or screenshot files from game folder
    folder = os.path.join(GAMES_DIR, game_name)
    if not os.path.isdir(folder):
        abort(404)
    file_path = os.path.join(folder, filename)
    if not os.path.isfile(file_path):
        abort(404)
    return send_from_directory(folder, filename)


@app.route('/games')
def list_games():
    if not os.path.isdir(GAMES_DIR):
        return jsonify([])
    games = []
    for name in os.listdir(GAMES_DIR):
        folder = os.path.join(GAMES_DIR, name)
        if not os.path.isdir(folder):
            continue
        meta_file = game_meta_path(name)
        meta = {}
        if os.path.isfile(meta_file):
            try:
                with open(meta_file, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
            except Exception:
                meta = {'error': 'invalid meta'}
        meta = normalize_meta(meta)
        has_zip = os.path.isfile(game_zip_path(name))
        # collect artwork files if present
        thumb = meta.get('thumbnail')
        screenshots = meta.get('screenshots', [])
        art = {}
        if thumb:
            art['thumbnail'] = f'/art/{name}/{thumb}'
        # validate screenshots exist
        valid_scr = []
        for s in screenshots:
            if os.path.isfile(os.path.join(folder, s)):
                valid_scr.append(f'/art/{name}/{s}')
        if valid_scr:
            art['screenshots'] = valid_scr

        games.append({'name': name, 'meta': meta, 'has_zip': has_zip, 'art': art})
    return jsonify(games)


@app.route('/meta/<game_name>')
def get_meta(game_name):
    meta_file = game_meta_path(game_name)
    if not os.path.isfile(meta_file):
        abort(404)
    try:
        with open(meta_file, 'r', encoding='utf-8') as f:
            meta = json.load(f)
    except Exception:
        abort(500)
    meta = normalize_meta(meta)
    return jsonify(meta)


@app.route('/download/<game_name>')
def download_game(game_name):
    # Require authentication
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'unauthorized'}), 401
    token = auth.split(' ', 1)[1]
    user = get_user_from_access_token(token)
    if not user:
        return jsonify({'error': 'invalid token or expired'}), 401
    zip_path = game_zip_path(game_name)
    if not os.path.isfile(zip_path):
        abort(404)

    # Support HTTP Range requests for resume
    range_header = request.headers.get('Range', None)
    file_size = os.path.getsize(zip_path)
    if range_header:
        try:
            # Example: Range: bytes=500-
            units, rng = range_header.split('=', 1)
            start_str, end_str = rng.split('-', 1)
            start = int(start_str) if start_str else 0
            end = int(end_str) if end_str else file_size - 1
            if start >= file_size:
                return '', 416
        except Exception:
            start = 0
            end = file_size - 1

        def generate():
            with open(zip_path, 'rb') as f:
                f.seek(start)
                remaining = end - start + 1
                chunk_size = 8192
                while remaining > 0:
                    read_size = min(chunk_size, remaining)
                    data = f.read(read_size)
                    if not data:
                        break
                    yield data
                    remaining -= len(data)

        rv = app.response_class(generate(), status=206, mimetype='application/octet-stream')
        rv.headers['Content-Range'] = f'bytes {start}-{end}/{file_size}'
        rv.headers['Accept-Ranges'] = 'bytes'
        rv.headers['Content-Length'] = str(end - start + 1)
        rv.headers['Content-Disposition'] = f'attachment; filename="{os.path.basename(zip_path)}"'
        return rv

    # no range header: serve whole file
    return send_from_directory(os.path.dirname(zip_path), os.path.basename(zip_path), as_attachment=True)


@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'missing'}), 400
    users = load_users()
    if not valid_username(username) or not valid_password(password):
        return jsonify({'error': 'invalid_input'}), 400
    if username in users:
        return jsonify({'error': 'exists'}), 400
    salt, dk, iterations = _pbkdf2_hash(password)
    users[username] = {'pw': dk, 'salt': salt, 'iterations': iterations, 'games': []}
    save_users(users)
    return jsonify({'ok': True})


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'missing'}), 400
    users = load_users()
    u = users.get(username)
    if not u:
        return jsonify({'error': 'invalid'}), 401

    if not verify_password_entry(u, password):
        return jsonify({'error': 'invalid'}), 401

    # create access and refresh tokens
    access_token = str(uuid.uuid4())
    refresh_token = str(uuid.uuid4())
    now = int(time.time())
    access_expires = now + 3600
    refresh_expires = now + 7 * 24 * 3600
    ACCESS_SESSIONS[access_token] = {'username': username, 'expires': access_expires}
    REFRESH_SESSIONS[refresh_token] = {'username': username, 'expires': refresh_expires}
    save_sessions()
    return jsonify({'token': access_token, 'refresh_token': refresh_token, 'username': username, 'expires_in': 3600})


@app.route('/auth/whoami')
def whoami():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth.split(' ', 1)[1]
        user = get_user_from_access_token(token)
        if user:
            return jsonify({'username': user})
    return jsonify({'username': None}), 401


@app.route('/auth/refresh', methods=['POST'])
def refresh():
    data = request.get_json(force=True)
    rtoken = data.get('refresh_token')
    if not rtoken:
        return jsonify({'error': 'missing'}), 400
    sess = REFRESH_SESSIONS.get(rtoken)
    if not sess or sess.get('expires', 0) < int(time.time()):
        return jsonify({'error': 'invalid_or_expired'}), 401
    username = sess['username']
    # issue new access token
    access_token = str(uuid.uuid4())
    access_expires = int(time.time()) + 3600
    ACCESS_SESSIONS[access_token] = {'username': username, 'expires': access_expires}
    save_sessions()
    return jsonify({'token': access_token, 'expires_in': 3600})


@app.route('/owned')
def owned():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'unauthorized'}), 401
    token = auth.split(' ', 1)[1]
    user = get_user_from_access_token(token)
    if not user:
        return jsonify({'error': 'invalid token or expired'}), 401
    users = load_users()
    u = users.get(user, {})
    return jsonify({'owned': u.get('games', [])})


@app.route('/version/<game_name>')
def version(game_name):
    g = sanitize_game_name(game_name)
    if not g:
        return jsonify({'error': 'invalid'}), 400
    meta_file = game_meta_path(g)
    if not os.path.isfile(meta_file):
        return jsonify({'error': 'not_found'}), 404
    try:
        with open(meta_file, 'r', encoding='utf-8') as f:
            meta = json.load(f)
        return jsonify({'version': meta.get('version')})
    except Exception:
        return jsonify({'error': 'invalid_meta'}), 500


@app.route('/checksum/<game_name>')
def checksum(game_name):
    zip_path = game_zip_path(game_name)
    if not os.path.isfile(zip_path):
        abort(404)
    # compute sha256
    h = hashlib.sha256()
    with open(zip_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return jsonify({'sha256': h.hexdigest()})


@app.route('/purchase/<game_name>', methods=['POST'])
def purchase(game_name):
    # stub: grant ownership without payment
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'unauthorized'}), 401
    token = auth.split(' ', 1)[1]
    user = get_user_from_access_token(token)
    if not user:
        return jsonify({'error': 'invalid token or expired'}), 401
    users = load_users()
    if game_name not in [d for d in os.listdir(GAMES_DIR) if os.path.isdir(os.path.join(GAMES_DIR, d))]:
        return jsonify({'error': 'game_not_found'}), 404
    u = users.get(user)
    if u is None:
        return jsonify({'error': 'user_not_found'}), 404
    owned = u.setdefault('games', [])
    if game_name in owned:
        return jsonify({'ok': True, 'already_owned': True})
    owned.append(game_name)
    save_users(users)
    return jsonify({'ok': True})


if __name__ == '__main__':
    os.makedirs(GAMES_DIR, exist_ok=True)
    # load sessions from disk
    access, refresh = load_sessions()
    # populate in-memory dictionaries with expirations
    now = int(time.time())
    for t, info in access.items():
        # if expired, skip
        if info.get('expires', 0) > now:
            ACCESS_SESSIONS[t] = info
    for t, info in refresh.items():
        if info.get('expires', 0) > now:
            REFRESH_SESSIONS[t] = info

    print('Server games directory:', GAMES_DIR)
    print('Users file:', USERS_FILE)
    print('Sessions file:', SESSIONS_FILE)
    app.run(host='0.0.0.0', port=5000, debug=True)


    
