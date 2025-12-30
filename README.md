# GameManager

Small server + client to host, download, extract and launch games.

Server
- Put games under `server/games/<GameName>/`.
- Each game folder should contain `<GameName>.zip` and `meta.json`.
- `meta.json` example:

```json
{
  "short": "Short Name",
  "description": "Full description goes here. Basic <b>HTML</b> works.",
  "executable_linux": "executable_linux",
  "execuatble_windows": "execuatble_windows.exe",
  "version": "0.0.0",
  "thumbnail": "thumb.png",
  "screenshots": ["ss1.png", "ss2.png"],
  "genres": ["Genre, tags"],
  "requirements": "Reqs"
}
```

Run server:

```bash
pip install -r requirements.txt
python3 server/app.py
```


Client
- PyQt5 GUI with two tabs: **Store** (list available games on the server) and **Library** (installed games).
- Supports user registration/login (`/auth/register` and `/auth/login`) and stores session token locally in `~/.gamemanager/config.json`.
- Dark mode toggle available from the toolbar. Theme is persisted in config.
- Downloads extract to `~/.gamemanager/installed/` and launching uses `wine` on Linux for `.exe` files.

Server API additions
- Authentication: PBKDF2 password hashing, access tokens (1h) and refresh tokens (7d).
- Endpoints:
  - `POST /auth/register` {username,password}
  - `POST /auth/login` {username,password} -> {token, refresh_token, expires_in}
  - `POST /auth/refresh` {refresh_token} -> {token}
  - `GET /owned` (Auth: Bearer) -> lists owned games
  - `POST /purchase/<game>` (Auth: Bearer) -> grants ownership (purchase stub)
  - `GET /download/<game>` (Auth: Bearer) -> requires authentication to download/install (no payments required)

Data files
- `server/users.json` stores user records and owned games.
- `server/sessions.json` stores issued access/refresh tokens with expiry.

Run client:

```bash
pip install -r requirements.txt
python3 client/app.py
```

Dirsributing the client:

**note, you HAVE to be on linux for this**

Environment variable `GM_SERVER` can point the client to a different server URL (defaults to `http://localhost:5000`).

Config file: `~/.gamemanager/config.json` stores `server`, `token`, `username`, and `theme`.

Docker
- Build and run the server in Docker (development):

```bash
docker build -t gamemanager .
docker run --rm -p 5000:5000 -v $(pwd)/server/games:/app/server/games gamemanager

Tests
- Quick smoke test (requires server running locally):

```bash
pip install -r requirements.txt
pytest -q tests/test_server_basic.py
```
```


