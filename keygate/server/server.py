"""
KeyGate Server — corre en TU PC y acepta conexiones autenticadas por token.
Author: Víctor Martín Sotoca
License: Apache 2.0

Uso:
    python server.py start          # arranca el servidor
    python server.py token create   # crea un token nuevo
    python server.py token list     # lista todos los tokens
    python server.py token revoke   # revoca un token
"""

import os
import sys
import json
import socket
import threading
import datetime
import argparse

# Añadir shared al path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from shared.models import Token, TokenStore, Perm

# ── Configuración ────────────────────────────────────────────────────────────
DATA_DIR    = os.path.expanduser("~/.keygate")
TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
LOG_FILE    = os.path.join(DATA_DIR, "server.log")

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 7331

os.makedirs(DATA_DIR, exist_ok=True)

# ── Logger simple ────────────────────────────────────────────────────────────
def log(msg: str, level="INFO"):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ── Protocolo de mensajes ────────────────────────────────────────────────────
# Cada mensaje es una línea JSON terminada en \n
# Request:  {"action": "...", "token": "...", "payload": {...}}
# Response: {"ok": true/false, "data": {...}, "error": "..."}

def send_msg(sock: socket.socket, obj: dict):
    data = json.dumps(obj) + "\n"
    sock.sendall(data.encode())

def recv_msg(sock: socket.socket) -> dict:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Conexión cerrada")
        buf += chunk
    return json.loads(buf.decode().strip())


# ── Acciones del servidor ────────────────────────────────────────────────────
class KeyGateServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host  = host
        self.port  = port
        self.store = TokenStore(TOKENS_FILE)

    def handle_client(self, conn: socket.socket, addr):
        ip = addr[0]
        log(f"Conexión entrante desde {ip}")
        try:
            req = recv_msg(conn)
            action = req.get("action", "")
            raw_token = req.get("token", "")
            payload   = req.get("payload", {})

            # Validar token
            tok = self.store.get_by_raw(raw_token)
            if not tok:
                send_msg(conn, {"ok": False, "error": "Token inválido"})
                log(f"{ip} → token inválido", "WARN")
                return

            valid, reason = tok.is_valid()
            if not valid:
                send_msg(conn, {"ok": False, "error": reason})
                log(f"{ip} → {reason} (token: {tok.name})", "WARN")
                return

            self.store.touch(tok.token_id)
            log(f"{ip} → acción '{action}' con token '{tok.name}' perms={tok.perms}")

            # Despachar acción
            result = self.dispatch(action, tok, payload)
            send_msg(conn, result)

        except Exception as e:
            log(f"Error con {ip}: {e}", "ERROR")
            try:
                send_msg(conn, {"ok": False, "error": str(e)})
            except:
                pass
        finally:
            conn.close()

    def dispatch(self, action: str, tok: Token, payload: dict) -> dict:
        # ── READ ──────────────────────────────────────────────────────────────
        if action == "ping":
            return {"ok": True, "data": {"pong": True, "server": socket.gethostname()}}

        if action == "info":
            if not tok.has_perm(Perm.READ):
                return {"ok": False, "error": "Permiso denegado: necesitas 'read'"}
            import platform
            return {"ok": True, "data": {
                "hostname": socket.gethostname(),
                "os":       platform.system() + " " + platform.release(),
                "python":   platform.python_version(),
                "time":     datetime.datetime.now().isoformat(),
            }}

        if action == "read_file":
            if not tok.has_perm(Perm.READ):
                return {"ok": False, "error": "Permiso denegado: necesitas 'read'"}
            path = payload.get("path", "")
            path = os.path.expanduser(path)
            if not os.path.exists(path):
                return {"ok": False, "error": f"Archivo no encontrado: {path}"}
            if os.path.getsize(path) > 1_000_000:
                return {"ok": False, "error": "Archivo demasiado grande (>1MB)"}
            with open(path) as f:
                content = f.read()
            return {"ok": True, "data": {"path": path, "content": content}}

        if action == "list_dir":
            if not tok.has_perm(Perm.READ):
                return {"ok": False, "error": "Permiso denegado: necesitas 'read'"}
            path = os.path.expanduser(payload.get("path", "~"))
            if not os.path.isdir(path):
                return {"ok": False, "error": "No es un directorio"}
            entries = []
            for e in os.scandir(path):
                entries.append({"name": e.name, "is_dir": e.is_dir(), "size": e.stat().st_size if e.is_file() else 0})
            return {"ok": True, "data": {"path": path, "entries": entries}}

        # ── WRITE ─────────────────────────────────────────────────────────────
        if action == "write_file":
            if not tok.has_perm(Perm.WRITE):
                return {"ok": False, "error": "Permiso denegado: necesitas 'write'"}
            path    = os.path.expanduser(payload.get("path", ""))
            content = payload.get("content", "")
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
            return {"ok": True, "data": {"written": len(content), "path": path}}

        if action == "delete_file":
            if not tok.has_perm(Perm.WRITE):
                return {"ok": False, "error": "Permiso denegado: necesitas 'write'"}
            path = os.path.expanduser(payload.get("path", ""))
            if not os.path.exists(path):
                return {"ok": False, "error": "Archivo no encontrado"}
            os.remove(path)
            return {"ok": True, "data": {"deleted": path}}

        # ── ADMIN ─────────────────────────────────────────────────────────────
        if action == "exec":
            if not tok.has_perm(Perm.ADMIN):
                return {"ok": False, "error": "Permiso denegado: necesitas 'admin'"}
            import subprocess
            cmd = payload.get("cmd", "")
            if not cmd:
                return {"ok": False, "error": "Comando vacío"}
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return {"ok": True, "data": {
                "stdout":      result.stdout,
                "stderr":      result.stderr,
                "returncode":  result.returncode,
            }}

        return {"ok": False, "error": f"Acción desconocida: '{action}'"}

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(20)
        log(f"KeyGate Server escuchando en {self.host}:{self.port}")
        log(f"Datos en {DATA_DIR}")
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
            t.start()


# ── CLI ──────────────────────────────────────────────────────────────────────
def cmd_start(args):
    store = TokenStore(TOKENS_FILE)
    if not store.all():
        print("AVISO: No hay tokens. Crea uno primero con:  python server.py token create")
    server = KeyGateServer(host=args.host, port=args.port)
    server.run()


def cmd_token_create(args):
    store = TokenStore(TOKENS_FILE)

    print("\n╔══════════════════════════════╗")
    print("║   KeyGate — Crear Token      ║")
    print("╚══════════════════════════════╝\n")

    name = input("Nombre del token: ").strip()
    if not name:
        print("ERROR: El nombre no puede estar vacío")
        return

    print(f"Permisos disponibles: {', '.join(Perm.ALL)}")
    raw_perms = input("Permisos (separados por coma, ej: read,write): ").strip()
    perms = [p.strip() for p in raw_perms.split(",") if p.strip()]
    if not Perm.validate(perms):
        print(f"ERROR: Permisos inválidos. Usa: {Perm.ALL}")
        return

    exp_str = input("Expiración en días (vacío = sin límite): ").strip()
    expires = int(exp_str) if exp_str.isdigit() else None

    note = input("Nota (opcional): ").strip()

    tok, raw = Token.generate(name=name, perms=perms, expires_days=expires, note=note)
    store.add(tok)

    print("\nToken creado exitosamente\n")
    print(f"  Nombre  : {tok.name}")
    print(f"  ID      : {tok.token_id}")
    print(f"  Permisos: {', '.join(tok.perms)}")
    print(f"  Expira  : {tok.expires_at or 'Nunca'}")
    print(f"\n  TOKEN (cópialo ahora, no se volverá a mostrar):")
    print(f"\n     {raw}\n")


def cmd_token_list(args):
    store = TokenStore(TOKENS_FILE)
    tokens = store.all()
    if not tokens:
        print("No hay tokens registrados.")
        return

    print(f"\n{'ID':10}  {'Nombre':20}  {'Permisos':20}  {'Expira':20}  {'Estado':10}  {'Último uso'}")
    print("─" * 110)
    for tok in tokens:
        valid, reason = tok.is_valid()
        estado = "OK" if valid else f"REVOCADO: {reason}"
        expira = tok.expires_at[:10] if tok.expires_at else "Nunca"
        uso    = tok.last_used[:16].replace("T"," ") if tok.last_used else "Nunca"
        perms  = ",".join(tok.perms)
        print(f"{tok.token_id:10}  {tok.name:20}  {perms:20}  {expira:20}  {estado:12}  {uso}")
    print()


def cmd_token_revoke(args):
    store = TokenStore(TOKENS_FILE)
    cmd_token_list(args)
    tid = input("ID del token a revocar: ").strip()
    if store.revoke(tid):
        print(f"Token {tid} revocado.")
    else:
        print(f"ERROR: Token no encontrado: {tid}")


def main():
    parser = argparse.ArgumentParser(description="KeyGate Server")
    sub = parser.add_subparsers(dest="command")

    # start
    p_start = sub.add_parser("start", help="Arrancar el servidor")
    p_start.add_argument("--host", default=DEFAULT_HOST)
    p_start.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_start.set_defaults(func=cmd_start)

    # token
    p_token = sub.add_parser("token", help="Gestión de tokens")
    tsub = p_token.add_subparsers(dest="subcmd")

    p_create = tsub.add_parser("create", help="Crear token")
    p_create.set_defaults(func=cmd_token_create)

    p_list = tsub.add_parser("list", help="Listar tokens")
    p_list.set_defaults(func=cmd_token_list)

    p_revoke = tsub.add_parser("revoke", help="Revocar token")
    p_revoke.set_defaults(func=cmd_token_revoke)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
