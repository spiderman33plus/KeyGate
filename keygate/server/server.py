"""  
KeyGate Server — corre en TU PC y acepta conexiones autenticadas por token.  
Author: Víctor Martín Sotoca  
License: Apache 2.0  
  
Uso:  
    python server.py start          # arranca el servidor (solo localhost)  
    python server.py start --host 0.0.0.0   # expone a la red (¡precaución!)  
    python server.py token create   # crea un token nuevo  
    python server.py token list     # lista todos los tokens  
    python server.py token revoke   # revoca un token  
"""  
  
import os  
import sys  
import json  
import hmac  
import time  
import shlex  
import socket  
import platform  
import threading  
import datetime  
import argparse  
import subprocess  
  
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  
from shared.models import Token, TokenStore, Perm  
from shared.protocol import send_msg, recv_msg  
  
# ── Configuración ────────────────────────────────────────────────────────────  
DATA_DIR      = os.path.expanduser("~/.keygate")  
TOKENS_FILE   = os.path.join(DATA_DIR, "tokens.json")  
CONFIG_FILE   = os.path.join(DATA_DIR, "config.json")  
LOG_FILE      = os.path.join(DATA_DIR, "server.log")  
SANDBOX_ROOT  = os.path.join(DATA_DIR, "files")   # archivos solo dentro de aquí  
  
DEFAULT_HOST  = "127.0.0.1"   # solo localhost por defecto (antes era 0.0.0.0)  
DEFAULT_PORT  = 7331  
  
MAX_FILE_SIZE = 1_000_000     # 1 MB  
CONN_TIMEOUT  = 15            # segundos  
  
# ── Rate limiting: bloqueo de IPs con demasiados tokens inválidos ────────────  
MAX_FAILED_ATTEMPTS = 5  
BAN_SECONDS         = 10 * 60   # 10 minutos  
  
# ── Allowlist de comandos para la acción 'exec' ──────────────────────────────  
# Solo estos comandos pueden ejecutarse, y SIN shell (no hay pipes, ni &&, ni >).  
# Nada de esto puede instalar software ni modificar el sistema.  
EXEC_ENABLED  = True  
EXEC_ALLOWLIST = {  
    "ls", "dir", "pwd", "whoami", "hostname", "date",  
    "uptime", "df", "du", "free", "uname", "echo", "ping",  
}  
EXEC_TIMEOUT  = 30  
  
os.makedirs(DATA_DIR, exist_ok=True)  
os.makedirs(SANDBOX_ROOT, exist_ok=True)  
  
# ── Logger ───────────────────────────────────────────────────────────────────  
def log(msg: str, level="INFO"):  
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  
    line = f"[{ts}] [{level}] {msg}"  
    print(line)  
    with open(LOG_FILE, "a") as f:  
        f.write(line + "\n")  
  
  
# ── Sandbox: resuelve una ruta del cliente y la encierra en SANDBOX_ROOT ─────  
def resolve_in_sandbox(user_path: str) -> str:  
    """  
    El cliente manda rutas relativas al sandbox (ej: 'docs/nota.txt').  
    '~' también apunta al sandbox. Cualquier intento de salir (../, rutas  
    absolutas del sistema, symlinks) se rechaza.  
    """  
    user_path = (user_path or "").strip()  
    if not user_path or user_path == "~":  
        return SANDBOX_ROOT  
    if user_path.startswith("~/"):  
        user_path = user_path[2:]  
    # Si mandan ruta absoluta, la tratamos como relativa al sandbox  
    user_path = user_path.lstrip("/").lstrip("\\")  
    candidate = os.path.realpath(os.path.join(SANDBOX_ROOT, user_path))  
    root = os.path.realpath(SANDBOX_ROOT)  
    if candidate != root and not candidate.startswith(root + os.sep):  
        raise PermissionError(f"Ruta fuera del sandbox: {user_path}")  
    return candidate  
  
  
# ── Servidor ─────────────────────────────────────────────────────────────────  
class KeyGateServer:  
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):  
        self.host  = host  
        self.port  = port  
        self.store = TokenStore(TOKENS_FILE)  
        # {ip: (fallos, banned_until_timestamp)}  
        self._failures: dict[str, tuple[int, float]] = {}  
        self._lock = threading.Lock()  
  
    # ── Rate limiting ────────────────────────────────────────────────────────  
    def _is_banned(self, ip: str) -> bool:  
        with self._lock:  
            fails, banned_until = self._failures.get(ip, (0, 0))  
            if banned_until and time.time() < banned_until:  
                return True  
            if banned_until and time.time() >= banned_until:  
                del self._failures[ip]  
            return False  
  
    def _register_failure(self, ip: str):  
        with self._lock:  
            fails, _ = self._failures.get(ip, (0, 0))  
            fails += 1  
            banned_until = 0  
            if fails >= MAX_FAILED_ATTEMPTS:  
                banned_until = time.time() + BAN_SECONDS  
                fails = 0  
                log(f"{ip} BANEADA por {BAN_SECONDS//60} min (demasiados tokens inválidos)", "WARN")  
            self._failures[ip] = (fails, banned_until)  
  
    # ── Conexión ─────────────────────────────────────────────────────────────  
    def handle_client(self, conn: socket.socket, addr):  
        ip = addr[0]  
        conn.settimeout(CONN_TIMEOUT)  
        try:  
            if self._is_banned(ip):  
                log(f"{ip} → rechazada (IP baneada)", "WARN")  
                send_msg(conn, {"ok": False, "error": "IP bloqueada temporalmente"})  
                return  
  
            log(f"Conexión entrante desde {ip}")  
            req       = recv_msg(conn)  
            action    = req.get("action", "")  
            raw_token = req.get("token", "")  
            payload   = req.get("payload", {})  
  
            tok = self.store.get_by_raw(raw_token)  
            if not tok:  
                self._register_failure(ip)  
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
  
            result = self.dispatch(action, tok, payload)  
            send_msg(conn, result)  
  
        except (socket.timeout, TimeoutError):  
            log(f"{ip} → timeout", "WARN")  
        except Exception as e:  
            log(f"Error con {ip}: {e}", "ERROR")  
            try:  
                send_msg(conn, {"ok": False, "error": str(e)})  
            except Exception:  
                pass  
        finally:  
            conn.close()  
  
    # ── Acciones ─────────────────────────────────────────────────────────────  
    def dispatch(self, action: str, tok: Token, payload: dict) -> dict:  
        if action == "ping":  
            return {"ok": True, "data": {"pong": True, "server": socket.gethostname()}}  
  
        if action == "info":  
            if not tok.has_perm(Perm.READ):  
                return {"ok": False, "error": "Permiso denegado: necesitas 'read'"}  
            return {"ok": True, "data": {  
                "hostname": socket.gethostname(),  
                "os":       platform.system() + " " + platform.release(),  
                "python":   platform.python_version(),  
                "time":     datetime.datetime.now().isoformat(),  
            }}  
  
        if action == "read_file":  
            if not tok.has_perm(Perm.READ):  
                return {"ok": False, "error": "Permiso denegado: necesitas 'read'"}  
            try:  
                path = resolve_in_sandbox(payload.get("path", ""))  
            except PermissionError as e:  
                return {"ok": False, "error": str(e)}  
            if not os.path.isfile(path):  
                return {"ok": False, "error": f"Archivo no encontrado: {payload.get('path')}"}  
            if os.path.getsize(path) > MAX_FILE_SIZE:  
                return {"ok": False, "error": "Archivo demasiado grande (>1MB)"}  
            with open(path) as f:  
                content = f.read()  
            rel = os.path.relpath(path, SANDBOX_ROOT)  
            return {"ok": True, "data": {"path": rel, "content": content}}  
  
        if action == "list_dir":  
            if not tok.has_perm(Perm.READ):  
                return {"ok": False, "error": "Permiso denegado: necesitas 'read'"}  
            try:  
                path = resolve_in_sandbox(payload.get("path", "~"))  
            except PermissionError as e:  
                return {"ok": False, "error": str(e)}  
            if not os.path.isdir(path):  
                return {"ok": False, "error": "No es un directorio"}  
            entries = []  
            for e in os.scandir(path):  
                entries.append({"name": e.name, "is_dir": e.is_dir(),  
                                "size": e.stat().st_size if e.is_file() else 0})  
            rel = os.path.relpath(path, SANDBOX_ROOT)  
            return {"ok": True, "data": {"path": rel, "entries": entries}}  
  
        if action == "write_file":  
            if not tok.has_perm(Perm.WRITE):  
                return {"ok": False, "error": "Permiso denegado: necesitas 'write'"}  
            content = payload.get("content", "")  
            if len(content) > MAX_FILE_SIZE:  
                return {"ok": False, "error": "Contenido demasiado grande (>1MB)"}  
            try:  
                path = resolve_in_sandbox(payload.get("path", ""))  
            except PermissionError as e:  
                return {"ok": False, "error": str(e)}  
            os.makedirs(os.path.dirname(path), exist_ok=True)  
            with open(path, "w") as f:  
                f.write(content)  
            rel = os.path.relpath(path, SANDBOX_ROOT)  
            return {"ok": True, "data": {"written": len(content), "path": rel}}  
  
        if action == "delete_file":  
            if not tok.has_perm(Perm.WRITE):  
                return {"ok": False, "error": "Permiso denegado: necesitas 'write'"}  
            try:  
                path = resolve_in_sandbox(payload.get("path", ""))  
            except PermissionError as e:  
                return {"ok": False, "error": str(e)}  
            if not os.path.exists(path):  
                return {"ok": False, "error": "Archivo no encontrado"}  
            os.remove(path)  
            rel = os.path.relpath(path, SANDBOX_ROOT)  
            return {"ok": True, "data": {"deleted": rel}}  
  
        if action == "exec":  
            if not EXEC_ENABLED:  
                return {"ok": False, "error": "La acción 'exec' está desactivada en este servidor"}  
            if not tok.has_perm(Perm.ADMIN):  
                return {"ok": False, "error": "Permiso denegado: necesitas 'admin'"}  
            cmd = payload.get("cmd", "").strip()  
            if not cmd:  
                return {"ok": False, "error": "Comando vacío"}  
            try:  
                argv = shlex.split(cmd)  
            except ValueError as e:  
                return {"ok": False, "error": f"Comando mal formado: {e}"}  
            prog = os.path.basename(argv[0]).lower()  
            if prog not in EXEC_ALLOWLIST:  
                return {"ok": False, "error":  
                        f"Comando '{prog}' no permitido. Permitidos: {sorted(EXEC_ALLOWLIST)}"}  
            # shell=False → sin pipes, sin &&, sin redirecciones, sin inyección  
            try:  
                result = subprocess.run(argv, shell=False, capture_output=True,  
                                        text=True, timeout=EXEC_TIMEOUT)  
            except FileNotFoundError:  
                return {"ok": False, "error": f"Comando no existe en este sistema: {prog}"}  
            except subprocess.TimeoutExpired:  
                return {"ok": False, "error": f"Comando superó el límite de {EXEC_TIMEOUT}s"}  
            return {"ok": True, "data": {  
                "stdout":     result.stdout,  
                "stderr":     result.stderr,  
                "returncode": result.returncode,  
            }}  
  
        return {"ok": False, "error": f"Acción desconocida: '{action}'"}  
  
    def run(self):  
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
        srv.bind((self.host, self.port))  
        srv.listen(20)  
        log(f"KeyGate Server escuchando en {self.host}:{self.port}")  
        log(f"Datos en {DATA_DIR} — sandbox de archivos: {SANDBOX_ROOT}")  
        if self.host == "0.0.0.0":  
            log("AVISO: el servidor es accesible desde TODA la red. "  
                "Asegúrate de que solo tienen acceso IPs de confianza.", "WARN")  
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
        uso    = tok.last_used[:16].replace("T", " ") if tok.last_used else "Nunca"  
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
  
    p_start = sub.add_parser("start", help="Arrancar el servidor")  
    p_start.add_argument("--host", default=DEFAULT_HOST,  
                         help="Por defecto 127.0.0.1 (solo local). Usa 0.0.0.0 para exponer a la red.")  
    p_start.add_argument("--port", type=int, default=DEFAULT_PORT)  
    p_start.set_defaults(func=cmd_start)  
  
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
