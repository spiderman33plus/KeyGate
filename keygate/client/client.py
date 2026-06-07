"""
KeyGate Client — conéctate a un servidor KeyGate con tu token.
Author: Víctor Martín Sotoca
License: Apache 2.0

Uso rápido:
    python client.py --host 192.168.1.10 --token kg_xxx ping
    python client.py --host 192.168.1.10 --token kg_xxx info
    python client.py --host 192.168.1.10 --token kg_xxx read ~/archivo.txt
    python client.py --host 192.168.1.10 --token kg_xxx write ~/dest.txt "contenido"
    python client.py --host 192.168.1.10 --token kg_xxx ls ~/Documentos
    python client.py --host 192.168.1.10 --token kg_xxx exec "ls -la"
    python client.py --host 192.168.1.10 --token kg_xxx delete ~/archivo.txt

Perfil guardado (evita escribir host/token cada vez):
    python client.py profile save
    python client.py profile use <nombre>
"""

import os
import sys
import json
import socket
import argparse

# ── Config de perfiles ────────────────────────────────────────────────────────
CFG_DIR  = os.path.expanduser("~/.keygate")
PROF_FILE = os.path.join(CFG_DIR, "profiles.json")
os.makedirs(CFG_DIR, exist_ok=True)

DEFAULT_PORT = 7331


# ── Protocolo ────────────────────────────────────────────────────────────────
def send_msg(sock, obj):
    data = json.dumps(obj) + "\n"
    sock.sendall(data.encode())

def recv_msg(sock) -> dict:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Conexión cerrada por el servidor")
        buf += chunk
    return json.loads(buf.decode().strip())


# ── Conexión ─────────────────────────────────────────────────────────────────
def request(host: str, port: int, token: str, action: str, payload: dict = {}) -> dict:
    with socket.create_connection((host, port), timeout=10) as s:
        send_msg(s, {"action": action, "token": token, "payload": payload})
        return recv_msg(s)


# ── Utilidades de impresión ───────────────────────────────────────────────────
def ok(msg): print(f"[OK]  {msg}")
def err(msg): print(f"[ERROR]  {msg}"); sys.exit(1)

def print_result(res: dict):
    if not res.get("ok"):
        err(res.get("error", "Error desconocido"))
    data = res.get("data", {})
    return data


# ── Gestión de perfiles ───────────────────────────────────────────────────────
def load_profiles() -> dict:
    if os.path.exists(PROF_FILE):
        with open(PROF_FILE) as f:
            return json.load(f)
    return {}

def save_profiles(profiles: dict):
    with open(PROF_FILE, "w") as f:
        json.dump(profiles, f, indent=2)

def get_active_profile() -> dict:
    profiles = load_profiles()
    active = profiles.get("_active")
    if active and active in profiles:
        return profiles[active]
    return {}


# ── Comandos ──────────────────────────────────────────────────────────────────
def cmd_ping(host, port, token, args):
    res = request(host, port, token, "ping")
    data = print_result(res)
    ok(f"Servidor '{data.get('server')}' responde correctamente")


def cmd_info(host, port, token, args):
    res = request(host, port, token, "info")
    data = print_result(res)
    print(f"\n  Hostname : {data.get('hostname')}")
    print(f"  Sistema  : {data.get('os')}")
    print(f"  Python   : {data.get('python')}")
    print(f"  Hora     : {data.get('time')}\n")


def cmd_read(host, port, token, args):
    res = request(host, port, token, "read_file", {"path": args.path})
    data = print_result(res)
    print(data.get("content", ""))


def cmd_write(host, port, token, args):
    content = args.content
    # Leer de stdin si el contenido es "-"
    if content == "-":
        content = sys.stdin.read()
    res = request(host, port, token, "write_file", {"path": args.path, "content": content})
    data = print_result(res)
    ok(f"Escrito {data.get('written')} bytes en {data.get('path')}")


def cmd_delete(host, port, token, args):
    confirm = input(f"¿Seguro que quieres eliminar '{args.path}'? (s/N): ").strip().lower()
    if confirm != "s":
        print("Cancelado.")
        return
    res = request(host, port, token, "delete_file", {"path": args.path})
    data = print_result(res)
    ok(f"Eliminado: {data.get('deleted')}")


def cmd_ls(host, port, token, args):
    path = args.path if hasattr(args, "path") and args.path else "~"
    res  = request(host, port, token, "list_dir", {"path": path})
    data = print_result(res)
    print(f"\n  DIR  {data.get('path')}\n")
    for e in sorted(data.get("entries", []), key=lambda x: (not x["is_dir"], x["name"])):
        tag  = "[d]" if e["is_dir"] else "[f]"
        size = f"  {e['size']:>10} B" if not e["is_dir"] else ""
        print(f"    {tag}  {e['name']}{size}")
    print()


def cmd_exec(host, port, token, args):
    res  = request(host, port, token, "exec", {"cmd": args.cmd})
    data = print_result(res)
    if data.get("stdout"):
        print(data["stdout"], end="")
    if data.get("stderr"):
        print("[stderr]", data["stderr"], end="")
    rc = data.get("returncode", 0)
    if rc != 0:
        print(f"\nExit code: {rc}")


def cmd_profile_save(args):
    profiles = load_profiles()
    name  = input("Nombre del perfil: ").strip()
    host  = input("Host del servidor (IP o dominio): ").strip()
    port  = input(f"Puerto [{DEFAULT_PORT}]: ").strip() or str(DEFAULT_PORT)
    token = input("Token (kg_...): ").strip()
    profiles[name] = {"host": host, "port": int(port), "token": token}
    save_profiles(profiles)
    ok(f"Perfil '{name}' guardado")


def cmd_profile_use(args):
    profiles = load_profiles()
    available = [k for k in profiles if not k.startswith("_")]
    if not available:
        err("No hay perfiles guardados. Usa: python client.py profile save")
    if hasattr(args, "name") and args.name:
        name = args.name
    else:
        print("Perfiles disponibles:", ", ".join(available))
        name = input("Perfil a usar: ").strip()
    if name not in profiles:
        err(f"Perfil '{name}' no encontrado")
    profiles["_active"] = name
    save_profiles(profiles)
    p = profiles[name]
    ok(f"Perfil activo: '{name}'  {p['host']}:{p['port']}")


def cmd_profile_list(args):
    profiles = load_profiles()
    active = profiles.get("_active")
    entries = [(k, v) for k, v in profiles.items() if not k.startswith("_")]
    if not entries:
        print("No hay perfiles guardados.")
        return
    print()
    for name, p in entries:
        marker = " <- activo" if name == active else ""
        token_preview = p['token'][:12] + "..." if len(p['token']) > 12 else p['token']
        print(f"  {'*' if name == active else '-'}  {name:20}  {p['host']}:{p['port']}  token={token_preview}{marker}")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="KeyGate Client — conéctate a tu PC con tokens",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python client.py --host 192.168.1.10 --token kg_xxx ping
  python client.py --host 192.168.1.10 --token kg_xxx info
  python client.py --host 192.168.1.10 --token kg_xxx read ~/notas.txt
  python client.py --host 192.168.1.10 --token kg_xxx write ~/out.txt "hola mundo"
  python client.py --host 192.168.1.10 --token kg_xxx ls ~/Documentos
  python client.py --host 192.168.1.10 --token kg_xxx exec "df -h"
  python client.py profile save     # guardar perfil
  python client.py profile use dev  # activar perfil 'dev'
        """
    )

    parser.add_argument("--host",  help="IP o hostname del servidor")
    parser.add_argument("--port",  type=int, default=DEFAULT_PORT)
    parser.add_argument("--token", help="Token de acceso (kg_...)")

    sub = parser.add_subparsers(dest="command")

    # Acciones de conexión
    sub.add_parser("ping",   help="Verificar que el servidor responde")
    sub.add_parser("info",   help="Ver info del sistema remoto (requiere read)")

    p_read = sub.add_parser("read",   help="Leer un archivo remoto (requiere read)")
    p_read.add_argument("path")

    p_write = sub.add_parser("write",  help="Escribir un archivo remoto (requiere write)")
    p_write.add_argument("path")
    p_write.add_argument("content", help="Contenido (usa '-' para leer de stdin)")

    p_del = sub.add_parser("delete", help="Eliminar un archivo remoto (requiere write)")
    p_del.add_argument("path")

    p_ls = sub.add_parser("ls",     help="Listar directorio remoto (requiere read)")
    p_ls.add_argument("path", nargs="?", default="~")

    p_exec = sub.add_parser("exec",   help="Ejecutar comando remoto (requiere admin)")
    p_exec.add_argument("cmd")

    # Gestión de perfiles
    p_prof = sub.add_parser("profile", help="Gestión de perfiles de conexión")
    psub = p_prof.add_subparsers(dest="subcmd")
    psub.add_parser("save",  help="Guardar nuevo perfil")
    p_use = psub.add_parser("use",   help="Activar perfil")
    p_use.add_argument("name", nargs="?")
    psub.add_parser("list",  help="Listar perfiles")

    args = parser.parse_args()

    # ── Perfiles ──────────────────────────────────────────────────────────────
    if args.command == "profile":
        if args.subcmd == "save":   cmd_profile_save(args)
        elif args.subcmd == "use":  cmd_profile_use(args)
        elif args.subcmd == "list": cmd_profile_list(args)
        else: p_prof.print_help()
        return

    if not args.command:
        parser.print_help()
        return

    # Resolver host/token desde perfil activo si no se pasaron
    profile = get_active_profile()
    host  = args.host  or profile.get("host")
    port  = args.port  or profile.get("port",  DEFAULT_PORT)
    token = args.token or profile.get("token")

    if not host:
        err("Especifica --host o activa un perfil con: python client.py profile use <nombre>")
    if not token:
        err("Especifica --token o activa un perfil con: python client.py profile use <nombre>")

    # Despachar comando
    dispatch = {
        "ping":   cmd_ping,
        "info":   cmd_info,
        "read":   cmd_read,
        "write":  cmd_write,
        "delete": cmd_delete,
        "ls":     cmd_ls,
        "exec":   cmd_exec,
    }

    fn = dispatch.get(args.command)
    if fn:
        try:
            fn(host, port, token, args)
        except ConnectionRefusedError:
            err(f"No se pudo conectar a {host}:{port}. ¿Está el servidor corriendo?")
        except TimeoutError:
            err(f"Timeout conectando a {host}:{port}")
        except Exception as e:
            err(str(e))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
