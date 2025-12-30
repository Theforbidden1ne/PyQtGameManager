import sys
import os
import platform
import requests
import zipfile
import json
import subprocess
from pathlib import Path
import functools

from PyQt5 import QtWidgets, QtCore, QtGui

DEFAULT_SERVER = os.environ.get('GM_SERVER', 'http://localhost:5000')
APP_DIR = Path.home() / '.gamemanager'
INSTALL_DIR = APP_DIR / 'installed'
CONFIG_FILE = APP_DIR / 'config.json'
APP_DIR.mkdir(parents=True, exist_ok=True)
INSTALL_DIR.mkdir(parents=True, exist_ok=True)


def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
        except Exception:
            return {}
    return {}


def save_config(cfg: dict):
    try:
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding='utf-8')
    except Exception:
        pass


class LoginDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Login')
        self.setModal(True)
        self.resize(300, 120)
        l = QtWidgets.QVBoxLayout()
        self.setLayout(l)
        form = QtWidgets.QFormLayout()
        self.user = QtWidgets.QLineEdit()
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        form.addRow('Username:', self.user)
        form.addRow('Password:', self.password)
        l.addLayout(form)
        btns = QtWidgets.QHBoxLayout()
        self.login_btn = QtWidgets.QPushButton('Login')
        self.register_btn = QtWidgets.QPushButton('Register')
        btns.addWidget(self.login_btn)
        btns.addWidget(self.register_btn)
        l.addLayout(btns)


class StoreItemWidget(QtWidgets.QWidget):
    def __init__(self, game, parent=None):
        super().__init__(parent)
        self.game = game
        h = QtWidgets.QHBoxLayout()
        self.setLayout(h)
        # thumbnail
        thumb = game.get('art', {}).get('thumbnail')
        if thumb:
            self.thumb_label = QtWidgets.QLabel()
            try:
                resp = requests.get(f'{DEFAULT_SERVER}{thumb}', timeout=5)
                img = QtGui.QImage.fromData(resp.content)
                pix = QtGui.QPixmap.fromImage(img).scaled(96, 96, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
                self.thumb_label.setPixmap(pix)
            except Exception:
                self.thumb_label.setText('')
            h.addWidget(self.thumb_label)
        else:
            h.addSpacing(8)

        title_col = QtWidgets.QVBoxLayout()
        self.name = QtWidgets.QLabel(f"{game['name']} <small style='color:gray'>v{game.get('meta', {}).get('version','')}</small>")
        self.name.setTextFormat(QtCore.Qt.RichText)
        self.name.setStyleSheet('font-weight: bold;')
        self.desc = QtWidgets.QLabel(game.get('meta', {}).get('short', game.get('meta', {}).get('description', '')))
        self.desc.setStyleSheet('color: gray;')
        self.desc.setWordWrap(True)
        title_col.addWidget(self.name)
        title_col.addWidget(self.desc)
        # genre tags
        genres = game.get('meta', {}).get('genres', [])
        if genres:
            tags = QtWidgets.QLabel(' | '.join(genres))
            tags.setStyleSheet('color: #99a; font-size: 10px;')
            title_col.addWidget(tags)
        h.addLayout(title_col, 4)
        self.btn_download = QtWidgets.QPushButton('Download')
        h.addWidget(self.btn_download)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Game Manager')
        self.resize(900, 600)
        self.cfg = load_config()
        self.server = self.cfg.get('server', DEFAULT_SERVER)
        self.token = self.cfg.get('token')
        self.username = self.cfg.get('username')

        self._apply_theme(self.cfg.get('theme', 'light'))

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        v = QtWidgets.QVBoxLayout()
        central.setLayout(v)

        toolbar = QtWidgets.QToolBar()
        self.addToolBar(toolbar)
        # search box
        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText('Search store...')
        self.search_box.returnPressed.connect(self._on_search)
        toolbar.addWidget(self.search_box)
        # genre filter
        self.genre_filter = QtWidgets.QComboBox()
        self.genre_filter.addItem('All')
        self.genre_filter.currentIndexChanged.connect(self.refresh_store)
        toolbar.addWidget(self.genre_filter)
        # sort options
        self.sort_box = QtWidgets.QComboBox()
        self.sort_box.addItems(['Name', 'Version'])
        self.sort_box.currentIndexChanged.connect(self.refresh_store)
        toolbar.addWidget(self.sort_box)
        self.login_action = QtWidgets.QAction('Login', self)
        self.login_action.triggered.connect(self.show_login)
        toolbar.addAction(self.login_action)
        self.logout_action = QtWidgets.QAction('Logout', self)
        self.logout_action.triggered.connect(self.logout)
        toolbar.addAction(self.logout_action)
        self.theme_action = QtWidgets.QAction('Toggle Dark Mode', self)
        self.theme_action.triggered.connect(self.toggle_theme)
        toolbar.addAction(self.theme_action)

        self.tabs = QtWidgets.QTabWidget()
        v.addWidget(self.tabs)

        # Store tab
        self.store_tab = QtWidgets.QWidget()
        self.store_layout = QtWidgets.QVBoxLayout()
        self.store_tab.setLayout(self.store_layout)
        self.store_list = QtWidgets.QListWidget()
        self.store_layout.addWidget(self.store_list)
        # open detail page on click
        self.store_list.itemClicked.connect(self.open_store_page)
        self.refresh_store_btn = QtWidgets.QPushButton('Refresh Store')
        self.store_layout.addWidget(self.refresh_store_btn)
        self.refresh_store_btn.clicked.connect(self.refresh_store)
        self.tabs.addTab(self.store_tab, 'Store')

        # Library tab (tile-based)
        self.lib_tab = QtWidgets.QWidget()
        self.lib_layout = QtWidgets.QVBoxLayout()
        self.lib_tab.setLayout(self.lib_layout)

        # Scrollable grid area for tiles
        self.lib_scroll = QtWidgets.QScrollArea()
        self.lib_scroll.setWidgetResizable(True)
        self.lib_grid_container = QtWidgets.QWidget()
        self.lib_grid = QtWidgets.QGridLayout()
        self.lib_grid_container.setLayout(self.lib_grid)
        self.lib_scroll.setWidget(self.lib_grid_container)
        self.lib_layout.addWidget(self.lib_scroll)

        self.refresh_lib_btn = QtWidgets.QPushButton('Refresh Library')
        self.lib_layout.addWidget(self.refresh_lib_btn)
        self.refresh_lib_btn.clicked.connect(self.refresh_library)
        self.tabs.addTab(self.lib_tab, 'Library')

        # status / log
        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        v.addWidget(self.log, 1)

        self.refresh_store()
        self.refresh_library()
        self._update_login_state()
        # track running processes: name -> Popen
        self.processes = {}

    def _apply_theme(self, theme):
        if theme == 'dark':
            self.setStyleSheet('''
                QWidget { background: #2b2b2b; color: #e6e6e6 }
                QPushButton { background: #3c3c3c }
            ''')
        else:
            # light theme tweaks
            self.setStyleSheet('''
                QListWidget { background: #ffffff }
                QLabel { color: #222 }
            ''')

    def toggle_theme(self):
        cur = self.cfg.get('theme', 'light')
        nxt = 'dark' if cur != 'dark' else 'light'
        self.cfg['theme'] = nxt
        save_config(self.cfg)
        self._apply_theme(nxt)

    def log_msg(self, *parts):
        self.log.append(' '.join(str(p) for p in parts))

    def refresh_store(self):
        self.store_list.clear()
        try:
            r = requests.get(f'{self.server}/games', timeout=5)
            games = r.json()
        except Exception as e:
            self.log_msg('Failed to fetch store:', e)
            return
        # optional local search filter
        query = self.search_box.text().strip().lower() if hasattr(self, 'search_box') else ''
        # update genre filter choices
        genres = set()
        for g in games:
            for gen in g.get('meta', {}).get('genres', []):
                genres.add(gen)
        # repopulate genre box without triggering
        cur = self.genre_filter.currentText() if hasattr(self, 'genre_filter') else 'All'
        self.genre_filter.blockSignals(True)
        self.genre_filter.clear()
        self.genre_filter.addItem('All')
        for gen in sorted(genres):
            self.genre_filter.addItem(gen)
        if cur and cur in [self.genre_filter.itemText(i) for i in range(self.genre_filter.count())]:
            self.genre_filter.setCurrentText(cur)
        self.genre_filter.blockSignals(False)
        selected_genre = self.genre_filter.currentText() if hasattr(self, 'genre_filter') else 'All'
        sort_by = self.sort_box.currentText() if hasattr(self, 'sort_box') else 'Name'
        # filter and sort
        filtered = []
        for g in games:
            text = (g['name'] + ' ' + json.dumps(g.get('meta', {}))).lower()
            if query and query not in text:
                continue
            if selected_genre and selected_genre != 'All':
                if selected_genre not in g.get('meta', {}).get('genres', []):
                    continue
            filtered.append(g)

        if sort_by == 'Name':
            filtered.sort(key=lambda x: x['name'].lower())
        else:
            # sort by version (empty -> 0)
            def ver_key(x):
                v = x.get('meta', {}).get('version') or ''
                parts = [int(p) if p.isdigit() else 0 for p in v.split('.') if p]
                return parts
            filtered.sort(key=ver_key, reverse=True)

        for g in filtered:
            item = QtWidgets.QListWidgetItem()
            w = StoreItemWidget(g)
            w.btn_download.clicked.connect(functools.partial(self.download_game, g['name']))
            item.setSizeHint(w.sizeHint())
            self.store_list.addItem(item)
            self.store_list.setItemWidget(item, w)
        

    def refresh_library(self):
        # clear grid
        for i in reversed(range(self.lib_grid.count())):
            w = self.lib_grid.itemAt(i).widget()
            if w:
                w.setParent(None)

        row = 0
        col = 0
        cols = 3
        for d in sorted(INSTALL_DIR.iterdir()):
            if not d.is_dir():
                continue
            tile = QtWidgets.QFrame()
            tile.setFrameShape(QtWidgets.QFrame.StyledPanel)
            tile_layout = QtWidgets.QVBoxLayout()
            tile.setLayout(tile_layout)
            title = QtWidgets.QLabel(d.name)
            title.setAlignment(QtCore.Qt.AlignCenter)
            tile_layout.addWidget(title)
            # try to show description from local meta
            meta = {}
            local_meta = d / 'meta.json'
            if local_meta.exists():
                try:
                    meta = json.loads(local_meta.read_text(encoding='utf-8'))
                except Exception:
                    meta = {}
            desc = QtWidgets.QLabel(meta.get('description', ''))
            desc.setWordWrap(True)
            desc.setStyleSheet('color: gray;')
            tile_layout.addWidget(desc)
            btn_row = QtWidgets.QHBoxLayout()
            launch = QtWidgets.QPushButton('Launch')
            update_btn = QtWidgets.QPushButton('Update')
            kill = QtWidgets.QPushButton('Kill')
            remove = QtWidgets.QPushButton('Remove')
            btn_row.addWidget(launch)
            btn_row.addWidget(update_btn)
            btn_row.addWidget(kill)
            btn_row.addWidget(remove)
            tile_layout.addLayout(btn_row)
            launch.clicked.connect(functools.partial(self.launch_game, d.name))
            update_btn.clicked.connect(functools.partial(self.update_game, d.name))
            kill.clicked.connect(functools.partial(self.kill_game, d.name))
            remove.clicked.connect(functools.partial(self.remove_game, d.name))
            self.lib_grid.addWidget(tile, row, col)
            col += 1
            if col >= cols:
                col = 0
                row += 1

    def show_login(self):
        dlg = LoginDialog(self)
        dlg.login_btn.clicked.connect(lambda: self._attempt_login(dlg))
        dlg.register_btn.clicked.connect(lambda: self._attempt_register(dlg))
        dlg.exec_()

    def _attempt_register(self, dlg: LoginDialog):
        user = dlg.user.text().strip()
        pw = dlg.password.text()
        if not user or not pw:
            self.log_msg('Enter username and password')
            return
        try:
            r = requests.post(f'{self.server}/auth/register', json={'username': user, 'password': pw}, timeout=5)
            if r.status_code == 200:
                self.log_msg('Registered. You can now login.')
            else:
                self.log_msg('Register failed:', r.json())
        except Exception as e:
            self.log_msg('Register error:', e)

    def _attempt_login(self, dlg: LoginDialog):
        user = dlg.user.text().strip()
        pw = dlg.password.text()
        if not user or not pw:
            self.log_msg('Enter username and password')
            return
        try:
            r = requests.post(f'{self.server}/auth/login', json={'username': user, 'password': pw}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                token = data.get('token')
                self.token = token
                self.username = data.get('username')
                self.cfg['token'] = token
                self.cfg['username'] = self.username
                save_config(self.cfg)
                self.log_msg('Login successful as', self.username)
                dlg.accept()
                self._update_login_state()
            else:
                self.log_msg('Login failed:', r.json())
        except Exception as e:
            self.log_msg('Login error:', e)

    def _update_login_state(self):
        if self.username:
            self.login_action.setEnabled(False)
            self.logout_action.setEnabled(True)
            self.setWindowTitle(f'Game Manager — {self.username}')
        else:
            self.login_action.setEnabled(True)
            self.logout_action.setEnabled(False)
            self.setWindowTitle('Game Manager')

    def logout(self):
        self.token = None
        self.username = None
        self.cfg.pop('token', None)
        self.cfg.pop('username', None)
        save_config(self.cfg)
        self._update_login_state()

    def download_game(self, name: str):
        # require login
        if not self.token:
            self.log_msg('Please login to download.')
            self.show_login()
            if not self.token:
                return

        url = f'{self.server}/download/{name}'
        local_zip = INSTALL_DIR / f'{name}.zip'
        headers = {}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'

        # support resume: check existing size
        existing = local_zip.stat().st_size if local_zip.exists() else 0

        # If we have partial file, probe remote to discover total size and avoid invalid ranges
        if existing > 0:
            try:
                probe = requests.get(url, headers={**headers, 'Range': 'bytes=0-0'}, timeout=10)
                # If server responds with 206, Content-Range gives total
                if probe.status_code == 206 and 'Content-Range' in probe.headers:
                    try:
                        total = int(probe.headers.get('Content-Range').split('/')[1])
                    except Exception:
                        total = None
                    if total is not None and existing >= total:
                        # already fully downloaded
                        self.log_msg('Local file already complete; verifying...')
                        # verify checksum like below
                        try:
                            rc = requests.get(f'{self.server}/checksum/{name}', timeout=5, headers={'Authorization': f'Bearer {self.token}'})
                            if rc.status_code == 200:
                                remote_sum = rc.json().get('sha256')
                                import hashlib as _hash
                                h = _hash.sha256()
                                with open(local_zip, 'rb') as fh:
                                    for chunk in iter(lambda: fh.read(8192), b''):
                                        h.update(chunk)
                                local_sum = h.hexdigest()
                                if remote_sum and local_sum == remote_sum:
                                    self.log_msg('Checksum OK; extracting')
                                    self.extract_zip(name, local_zip)
                                    self.refresh_library()
                                    return
                        except Exception:
                            pass
                        # not verified; fall through to re-download
                elif probe.status_code == 416:
                    # server says range not satisfiable -> likely local file equals remote
                    self.log_msg('Server returned 416 for probe; treating file as complete and verifying')
                    try:
                        rc = requests.get(f'{self.server}/checksum/{name}', timeout=5, headers={'Authorization': f'Bearer {self.token}'})
                        if rc.status_code == 200:
                            remote_sum = rc.json().get('sha256')
                            import hashlib as _hash
                            h = _hash.sha256()
                            with open(local_zip, 'rb') as fh:
                                for chunk in iter(lambda: fh.read(8192), b''):
                                    h.update(chunk)
                            local_sum = h.hexdigest()
                            if remote_sum and local_sum == remote_sum:
                                self.log_msg('Checksum OK; extracting')
                                self.extract_zip(name, local_zip)
                                self.refresh_library()
                                return
                    except Exception:
                        pass
                # otherwise we will request a range from existing
                headers['Range'] = f'bytes={existing}-'
            except Exception:
                # probe failed; attempt resume anyway
                headers['Range'] = f'bytes={existing}-'

        try:
            with requests.get(url, stream=True, timeout=30, headers=headers) as r:
                if r.status_code == 401:
                    self.log_msg('Auth failed; please login again.')
                    return
                if r.status_code not in (200, 206):
                    self.log_msg('Download failed, status:', r.status_code)
                    return

                total = None
                if 'Content-Range' in r.headers:
                    # parse total from header like: bytes start-end/total
                    try:
                        total = int(r.headers.get('Content-Range').split('/')[1])
                    except Exception:
                        total = None
                else:
                    try:
                        total = int(r.headers.get('Content-Length', 0))
                    except Exception:
                        total = None

                mode = 'ab' if r.status_code == 206 and existing > 0 else 'wb'
                self.log_msg('Downloading', name)
                # progress dialog
                pd = QtWidgets.QProgressDialog(f'Downloading {name}...', 'Cancel', 0, total or 0, self)
                pd.setWindowModality(QtCore.Qt.WindowModal)
                pd.setMinimumDuration(200)
                written = existing
                with open(local_zip, mode) as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            written += len(chunk)
                            if total:
                                pd.setMaximum(total)
                                pd.setValue(written)
                            QtWidgets.QApplication.processEvents()
                            if pd.wasCanceled():
                                self.log_msg('Download canceled')
                                return
                pd.close()

            # verify checksum if available
            try:
                rc = requests.get(f'{self.server}/checksum/{name}', timeout=5, headers={'Authorization': f'Bearer {self.token}'})
                if rc.status_code == 200:
                    remote_sum = rc.json().get('sha256')
                    import hashlib as _hash
                    h = _hash.sha256()
                    with open(local_zip, 'rb') as fh:
                        for chunk in iter(lambda: fh.read(8192), b''):
                            h.update(chunk)
                    local_sum = h.hexdigest()
                    if remote_sum and local_sum != remote_sum:
                        self.log_msg('Checksum mismatch after download!')
                        return
            except Exception:
                pass

            self.log_msg('Downloaded', local_zip)
            self.extract_zip(name, local_zip)
            self.refresh_library()
        except Exception as e:
            self.log_msg('Download failed:', e)

    def open_store_page(self, item: QtWidgets.QListWidgetItem):
        w = self.store_list.itemWidget(item)
        if not w:
            return
        game = w.game
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(game['name'])
        dlg.resize(500, 400)
        l = QtWidgets.QVBoxLayout()
        dlg.setLayout(l)
        # show header with thumbnail
        hdr = QtWidgets.QHBoxLayout()
        if game.get('art', {}).get('thumbnail'):
            try:
                resp = requests.get(f"{self.server}{game['art']['thumbnail']}", timeout=5)
                img = QtGui.QImage.fromData(resp.content)
                pix = QtGui.QPixmap.fromImage(img).scaled(160, 160, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
                lbl = QtWidgets.QLabel()
                lbl.setPixmap(pix)
                hdr.addWidget(lbl)
            except Exception:
                pass
        header_text = QtWidgets.QLabel(f"<h2>{game['name']}</h2>\n{game.get('meta', {}).get('short', '')}")
        hdr.addWidget(header_text)
        l.addLayout(hdr)
        meta = game.get('meta', {})
        about = QtWidgets.QLabel(meta.get('description', 'No description'))
        about.setWordWrap(True)
        l.addWidget(about)
        reqs = QtWidgets.QLabel('<b>Requirements</b>')
        l.addWidget(reqs)
        req_text = QtWidgets.QLabel(meta.get('requirements', 'None'))
        req_text.setWordWrap(True)
        l.addWidget(req_text)
        btn_row = QtWidgets.QHBoxLayout()
        buy_btn = QtWidgets.QPushButton('Buy')
        buy_btn.clicked.connect(lambda: self._purchase_and_download(game['name'], dlg))
        dl_btn = QtWidgets.QPushButton('Download')
        dl_btn.clicked.connect(lambda: (dlg.accept(), self.download_game(game['name'])))
        btn_row.addWidget(buy_btn)
        btn_row.addWidget(dl_btn)
        l.addLayout(btn_row)
        dlg.exec_()

    def _on_search(self):
        self.refresh_store()

    def _purchase_and_download(self, name: str, dlg=None):
        if not self.token:
            self.show_login()
            if not self.token:
                return
        try:
            r = requests.post(f'{self.server}/purchase/{name}', headers={'Authorization': f'Bearer {self.token}'}, timeout=5)
            if r.status_code in (200, 201):
                self.log_msg('Purchased', name)
            else:
                self.log_msg('Purchase response:', r.status_code, r.text)
        except Exception as e:
            self.log_msg('Purchase failed:', e)
        if dlg:
            dlg.accept()
        self.download_game(name)

    def kill_game(self, name: str):
        proc = self.processes.get(name)
        if not proc:
            self.log_msg('No running process for', name)
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
            self.log_msg('Terminated', name)
        except Exception:
            try:
                proc.kill()
                self.log_msg('Killed', name)
            except Exception as e:
                self.log_msg('Failed to kill process:', e)
        finally:
            self.processes.pop(name, None)

    def extract_zip(self, name: str, zip_path: Path):
        target = INSTALL_DIR / name
        if target.exists():
            # remove existing
            for p in target.rglob('*'):
                try:
                    if p.is_file():
                        p.unlink()
                except Exception:
                    pass
        target.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                z.extractall(target)
            self.log_msg('Extracted to', target)
        except Exception as e:
            self.log_msg('Extraction failed:', e)

    def read_meta(self, name: str):
        try:
            r = requests.get(f'{self.server}/meta/{name}', timeout=5)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        local_meta = INSTALL_DIR / name / 'meta.json'
        if local_meta.exists():
            try:
                return json.loads(local_meta.read_text(encoding='utf-8'))
            except Exception:
                return {}
        return {}

    def launch_game(self, name: str):
        target = INSTALL_DIR / name
        if not target.exists():
            self.log_msg('Game not installed. Please download first.')
            return
        meta = self.read_meta(name)
        # support multiple executable keys: generic or per-platform
        system = platform.system().lower()
        exe = None
        # prefer explicit generic key
        if 'executable' in meta and meta.get('executable'):
            exe = meta.get('executable')
            used_key = 'executable'
        else:
            if system == 'windows':
                exe = meta.get('executable_windows') or meta.get('executable_win')
                used_key = 'executable_windows' if exe else None
            elif system == 'darwin':
                exe = meta.get('executable_mac') or meta.get('executable_darwin')
                used_key = 'executable_mac' if exe else None
            else:
                exe = meta.get('executable_linux') or meta.get('executable_unix')
                used_key = 'executable_linux' if exe else None

        if not exe:
            self.log_msg('No executable specified in meta for', name)
            return
        if used_key:
            self.log_msg('Using executable from meta key', used_key, ':', exe)
        exe_path = target / exe
        if not exe_path.exists():
            self.log_msg('Executable not found at', exe_path)
            return
        system = platform.system().lower()
        if system == 'linux' and exe_path.suffix.lower() == '.exe':
            # use a per-game WINEPREFIX
            wine_prefix = APP_DIR / 'wineprefixes' / name
            wine_prefix.mkdir(parents=True, exist_ok=True)
            cmd = ['wine', str(exe_path)]
            env = os.environ.copy()
            env['WINEPREFIX'] = str(wine_prefix)
        else:
            if system == 'linux':
                try:
                    os.chmod(exe_path, os.stat(exe_path).st_mode | 0o111)
                except Exception:
                    pass
            cmd = [str(exe_path)]
        try:
            self.log_msg('Launching', ' '.join(cmd))
            if system == 'linux' and exe_path.suffix.lower() == '.exe':
                proc = subprocess.Popen(cmd, cwd=str(target), env=env)
            else:
                proc = subprocess.Popen(cmd, cwd=str(target))
            # track process so we can kill it later
            self.processes[name] = proc
        except Exception as e:
            self.log_msg('Launch failed:', e)

    def remove_game(self, name: str):
        target = INSTALL_DIR / name
        if not target.exists():
            self.log_msg('Not installed:', name)
            return
        # kill running process if exists
        if name in self.processes:
            try:
                self.log_msg('Killing running process for', name)
                self.processes[name].terminate()
                self.processes[name].wait(timeout=3)
            except Exception:
                try:
                    self.processes[name].kill()
                except Exception:
                    pass
            finally:
                self.processes.pop(name, None)
        for p in sorted(target.rglob('*'), reverse=True):
            try:
                if p.is_file():
                    p.unlink()
                elif p.is_dir():
                    p.rmdir()
            except Exception:
                pass
        try:
            target.rmdir()
        except Exception:
            pass
        zip_path = INSTALL_DIR / f'{name}.zip'
        if zip_path.exists():
            try:
                zip_path.unlink()
            except Exception:
                pass
        self.log_msg('Removed', name)
        self.refresh_library()

    def update_game(self, name: str):
        # check remote version, then download if newer
        try:
            r = requests.get(f'{self.server}/version/{name}', timeout=5)
            if r.status_code != 200:
                self.log_msg('Failed to fetch version for', name)
                return
            remote = r.json().get('version')
        except Exception as e:
            self.log_msg('Version check failed:', e)
            return
        # local version
        local_meta = INSTALL_DIR / name / 'meta.json'
        local_ver = None
        if local_meta.exists():
            try:
                local_ver = json.loads(local_meta.read_text(encoding='utf-8')).get('version')
            except Exception:
                local_ver = None
        if not remote:
            self.log_msg('No remote version available for', name)
            return
        if local_ver == remote:
            self.log_msg('Already up-to-date:', name)
            return
        self.log_msg('Updating', name, 'from', local_ver, 'to', remote)
        self.download_game(name)


def main():
    app = QtWidgets.QApplication(sys.argv)
    mw = MainWindow()
    mw.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
