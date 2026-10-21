"""  
KeyGate — protocolo de mensajes compartido entre cliente y servidor.  
Cada mensaje es una línea JSON terminada en \n.  
Request:  {"action": "...", "token": "...", "payload": {...}}  
Response: {"ok": true/false, "data": {...}, "error": "..."}  
"""  
  
import json  
import socket  
  
MAX_MSG_SIZE = 64 * 1024  # 64 KB máximo por mensaje  
  
  
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
        if len(buf) > MAX_MSG_SIZE:  
            raise ValueError("Mensaje demasiado grande (>64KB)")  
    return json.loads(buf.decode().strip())
